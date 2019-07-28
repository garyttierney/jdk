#include "EventStream.h"

void EventStream::begin(const EventType &type, intptr_t address) {
    emit(type.name(), (void*)address);
}

void EventStream::end(const EventType &type, intptr_t address) {
    std::string tag = "/" + type.name();
    emit(tag, (void*)address);
}

void *EventStream::emit(const EventType &type, intptr_t address) {
    std::string name = type.name() + "/";
    return emit(name, (void*) address);
}

void *EventStream::emit(const EventType &type, const std::string& value) {
    std::string name = type.name() + "/";
    return emit(name, (void*) value.c_str());
}