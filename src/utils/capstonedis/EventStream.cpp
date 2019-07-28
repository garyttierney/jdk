//
// Created by gtierney on 26/07/2019.
//

#include "EventStream.h"

void* EventStream::emit(Event& event)
{
    const char* name = event.name();
    void* arg = event.arg();

    return event_callback(event_stream, name, arg);
}
