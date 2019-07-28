#ifndef CAPSTONE_HSDIS_EVENTSTREAM_H
#define CAPSTONE_HSDIS_EVENTSTREAM_H

#include "capstone-hsdis.h"
#include <string>
#include <utility>

class EventType {
public:

    explicit EventType(std::string name) : _name(std::move(name)) {}

    const std::string & name() const {
        return _name;
    }

private:
    std::string _name;
};

static EventType EVENT_INSNS("insns");
static EventType EVENT_MACHINE("mach");
static EventType EVENT_INSN = EventType("insn");
static EventType EVENT_ADDR("addr");

class EventStream {
public:
    EventStream(event_callback_t _event_callback, void *_event_stream)
	: event_callback(_event_callback), event_stream(_event_stream) {
    }

    void begin(const EventType &type, intptr_t address);

    void end(const EventType &type, intptr_t address);

    void *emit(const EventType &type, intptr_t address);

    void *emit(const EventType &type, const std::string &value);
private:
    void *emit(const std::string &name, void *ptr) {
	return event_callback(event_stream, name.c_str(), ptr);
    }

    event_callback_t event_callback;
    void *event_stream;
};

#endif // CAPSTONE_HSDIS_EVENTSTREAM_H
