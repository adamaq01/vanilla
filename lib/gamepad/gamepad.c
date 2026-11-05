#define _GNU_SOURCE

#include "gamepad.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "audio.h"
#include "command.h"
#include "input.h"
#include "video.h"

#include "plugin/registry.h"
#include "transport/network.h"
#include "util.h"

// How long the session thread and the GamePad threads wait on the transport
// before checking whether they should stop
#define TRANSPORT_POLL_TIMEOUT_MS 250

#define EVENT_BUFFER_SIZE 65536
#define EVENT_BUFFER_ARENA_SIZE VANILLA_MAX_EVENT_COUNT * 2
uint8_t *EVENT_BUFFER_ARENA[EVENT_BUFFER_ARENA_SIZE] = {0};
pthread_mutex_t event_buffer_mutex = PTHREAD_MUTEX_INITIALIZER;

int send_to_console(gamepad_context_t *ctx, vanilla_channel_t channel, const void *data, size_t data_size)
{
    return ctx->transport->send(ctx->transport_ctx, channel, data, data_size);
}

int recv_from_console(gamepad_context_t *ctx, vanilla_channel_t channel, void *buf, size_t size)
{
    return ctx->transport->recv(ctx->transport_ctx, channel, buf, size, TRANSPORT_POLL_TIMEOUT_MS);
}

void wait_for_interrupt()
{
    while (!is_interrupted()) {
        usleep(100000);
    }
}

void sync_internal(thread_data_t *data)
{
    clear_interrupt();

    uint16_t code = (uintptr_t) data->thread_data;

    const vanilla_transport_t *transport;
    void *ctx = NULL;

    vanilla_sync_event_t syncdata;

    syncdata.status = open_selected_transport(&transport, &ctx);
    if (syncdata.status == VANILLA_SUCCESS) {
        syncdata.status = transport->start_sync(ctx, code);
    }

    if (syncdata.status == VANILLA_SUCCESS) {
        // Wait for sync result
        syncdata.status = VANILLA_ERR_PIPE_UNRESPONSIVE;
        while (!is_interrupted()) {
            int ret = transport->poll_sync(ctx, TRANSPORT_POLL_TIMEOUT_MS, &syncdata.data);
            if (ret != 0) {
                syncdata.status = (ret > 0) ? VANILLA_SUCCESS : ret;
                break;
            }
        }
    }

    if (syncdata.status == VANILLA_SUCCESS) {
        push_event(data->event_loop, VANILLA_EVENT_SYNC, &syncdata, sizeof(syncdata));
    } else {
        push_event(data->event_loop, VANILLA_EVENT_ERROR, &syncdata.status, sizeof(syncdata.status));
    }

    // Wait for interrupt so frontend has a chance to receive event
    wait_for_interrupt();

    if (ctx) {
        transport->base.close(ctx);
    }
}

int install_polkit_internal(thread_data_t *data, int install)
{
    clear_interrupt();

    return network_install_polkit(data->server_address, install);
}

void connect_as_gamepad_internal(thread_data_t *data)
{
    clear_interrupt();

    gamepad_context_t info;
    info.event_loop = data->event_loop;
    info.transport_ctx = NULL;

    vanilla_connection_t console;
    console.bssid = data->bssid;
    console.psk = data->psk;

    int ret = open_selected_transport(&info.transport, &info.transport_ctx);
    if (ret == VANILLA_SUCCESS) {
        ret = info.transport->start_connect(info.transport_ctx, &console);
    }

    if (ret == VANILLA_SUCCESS) {
        // Wait for the link to the console
        ret = VANILLA_ERR_NO_CONNECTION;
        while (!is_interrupted()) {
            int link_up = 0;
            int r = info.transport->poll_link(info.transport_ctx, TRANSPORT_POLL_TIMEOUT_MS, &link_up);
            if (r < 0) {
                ret = r;
                break;
            } else if (r > 0 && link_up) {
                ret = VANILLA_SUCCESS;
                break;
            }
        }
    }

    if (ret == VANILLA_SUCCESS) {
        pthread_t video_thread, audio_thread, input_thread, cmd_thread;

        int cnn = VANILLA_ERR_CONNECTED;
        push_event(data->event_loop, VANILLA_EVENT_ERROR, &cnn, sizeof(cnn));

        pthread_create(&video_thread, NULL, listen_video, &info);
        pthread_create(&audio_thread, NULL, listen_audio, &info);
        pthread_create(&input_thread, NULL, listen_input, &info);
        pthread_create(&cmd_thread, NULL, listen_command, &info);

#ifndef __APPLE__
		// macOS has a different implementation that requires this to be called
		// from the thread. Since thread name is only really important for
		// profiling, and that mostly happens on Linux, we just don't bother.
        pthread_setname_np(video_thread, "vanilla-video");
        pthread_setname_np(audio_thread, "vanilla-audio");
        pthread_setname_np(input_thread, "vanilla-input");
        pthread_setname_np(cmd_thread, "vanilla-cmd");
#endif

        while (!is_interrupted()) {
            int link_up = 0;
            int r = info.transport->poll_link(info.transport_ctx, TRANSPORT_POLL_TIMEOUT_MS, &link_up);
            if (r < 0) {
                // The transport is gone (e.g. its device was unplugged), so end
                // the session with its error
                ret = r;
                force_interrupt();
            } else if (r > 0) {
                cnn = link_up ? VANILLA_ERR_CONNECTED : VANILLA_ERR_DISCONNECTED;
                push_event(data->event_loop, VANILLA_EVENT_ERROR, &cnn, sizeof(cnn));
            }
        }

        pthread_join(video_thread, NULL);
        pthread_join(audio_thread, NULL);
        pthread_join(input_thread, NULL);
        pthread_join(cmd_thread, NULL);
    }

    if (info.transport_ctx) {
        info.transport->base.close(info.transport_ctx);
    }

    if (ret != VANILLA_SUCCESS) {
        push_event(info.event_loop, VANILLA_EVENT_ERROR, &ret, sizeof(ret));
    }

    // Wait for interrupt so frontend has a chance to receive event
    wait_for_interrupt();
}

int acquire_event(event_loop_t *loop, vanilla_event_t **event)
{
	int ret = VANILLA_SUCCESS;

    pthread_mutex_lock(&loop->mutex);

	// Prevent rollover by skipping oldest event if necessary
	if (loop->new_index == loop->used_index + VANILLA_MAX_EVENT_COUNT) {
		vanilla_free_event(&loop->events[loop->used_index % VANILLA_MAX_EVENT_COUNT]);
		vanilla_log("SKIPPED EVENT TO PREVENT ROLLOVER (%lu > %lu + %lu)", loop->new_index, loop->used_index, VANILLA_MAX_EVENT_COUNT);
		loop->used_index++;
	}

	vanilla_event_t *ev = &loop->events[loop->new_index % VANILLA_MAX_EVENT_COUNT];

	assert(!ev->data);

	ev->data = get_event_buffer();
	// if (!ev->data) {
	// 	vanilla_log("OUT OF MEMORY FOR NEW EVENTS");
	// 	ret = VANILLA_ERR_OUT_OF_MEMORY;
	// }

	*event = ev;

	return ret;
}

int release_event(event_loop_t *loop)
{
	loop->new_index++;

    pthread_cond_broadcast(&loop->waitcond);

    // } else {
    //     vanilla_log("FAILED TO PUSH EVENT: wanted %lu, only had %lu. This is a bug, please report to developers.", size, EVENT_BUFFER_SIZE);
    //     ret = VANILLA_ERR_INVALID_ARGUMENT;
    // }

exit:
    pthread_mutex_unlock(&loop->mutex);

    return VANILLA_SUCCESS;
}

int push_event(event_loop_t *loop, int type, const void *data, size_t size)
{
	vanilla_event_t *ev;

    int ret = acquire_event(loop, &ev);
	if (ret != VANILLA_SUCCESS) {
		return ret;
	}

	ev->type = type;
	memcpy(ev->data, data, size);
	ev->size = size;

	ret = release_event(loop);

	return ret;
}

int get_event(event_loop_t *loop, vanilla_event_t *event, int wait)
{
    int ret = 0;

    pthread_mutex_lock(&loop->mutex);

    if (loop->active) {
        if (wait) {
            while (loop->active && loop->used_index == loop->new_index) {
                pthread_cond_wait(&loop->waitcond, &loop->mutex);
            }
        }

        if (loop->active && loop->used_index < loop->new_index) {
            // Output data to pointer
            vanilla_event_t *pull_event = &loop->events[loop->used_index % VANILLA_MAX_EVENT_COUNT];

            event->type = pull_event->type;
            event->data = pull_event->data;
            event->size = pull_event->size;

            pull_event->data = NULL;

            loop->used_index++;
            ret = 1;
        }
    }

    pthread_mutex_unlock(&loop->mutex);

    return ret;
}

void *get_event_buffer()
{
    void *buf = NULL;

    pthread_mutex_lock(&event_buffer_mutex);
    for (size_t i = 0; i < EVENT_BUFFER_ARENA_SIZE; i++) {
        if (EVENT_BUFFER_ARENA[i]) {
            buf = EVENT_BUFFER_ARENA[i];
            EVENT_BUFFER_ARENA[i] = NULL;
            break;
    }
        }
    pthread_mutex_unlock(&event_buffer_mutex);

    return buf;
}

void release_event_buffer(void *buffer)
{
    pthread_mutex_lock(&event_buffer_mutex);
    for (size_t i = 0; i < EVENT_BUFFER_ARENA_SIZE; i++) {
        if (!EVENT_BUFFER_ARENA[i]) {
            EVENT_BUFFER_ARENA[i] = buffer;
            break;
        }
    }
    pthread_mutex_unlock(&event_buffer_mutex);
}

void init_event_buffer_arena()
{
    for (size_t i = 0; i < EVENT_BUFFER_ARENA_SIZE; i++) {
        if (!EVENT_BUFFER_ARENA[i]) {
            EVENT_BUFFER_ARENA[i] = malloc(EVENT_BUFFER_SIZE);
        } else {
            vanilla_log("CRITICAL: Buffer wasn't returned to the arena");
        }
    }
}

void free_event_buffer_arena()
{
    for (size_t i = 0; i < EVENT_BUFFER_ARENA_SIZE; i++) {
        if (EVENT_BUFFER_ARENA[i]) {
            free(EVENT_BUFFER_ARENA[i]);
            EVENT_BUFFER_ARENA[i] = NULL;
        } else {
            vanilla_log("CRITICAL: Buffer wasn't returned to the arena");
        }
    }
}
