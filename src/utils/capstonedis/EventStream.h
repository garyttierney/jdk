#ifndef CAPSTONE_HSDIS_EVENTSTREAM_H
#define CAPSTONE_HSDIS_EVENTSTREAM_H

#include "capstone-hsdis.h"
#include <string>
#include <utility>

class Event {
public:
    virtual const char* name() = 0;

    virtual void* arg() = 0;
};

class AddrEvent : public Event {
    void* arg() override { return reinterpret_cast<void*>(addr); }

protected:
    explicit AddrEvent(uintptr_t _addr)
        : addr(_addr)
    {
    }

private:
    uintptr_t addr;
};

class MemoryAddressEvent : public AddrEvent {
public:
    explicit MemoryAddressEvent(uintptr_t addr) : AddrEvent(addr) {}

    const char* name() override
    {
        return "addr/";
    }
};

class CStringEvent : public Event {
public:
    void* arg() override { return (void*)value.c_str(); }

protected:
    explicit CStringEvent(std::string _value)
        : value(std::move(_value))
    {
    }

private:
    std::string value;
};

class MachineInfo : public CStringEvent {
public:
    explicit MachineInfo(std::string ident)
        : CStringEvent(std::move(ident))
    {
    }

    const char* name() override { return "mach/"; }
};

class InstructionsStarted : public AddrEvent {
public:
    explicit InstructionsStarted(uintptr_t start)
        : AddrEvent(start)
    {
    }

    const char* name() override { return "insns"; }
};

class InstructionsCompleted : public AddrEvent {
public:
    explicit InstructionsCompleted(uintptr_t end)
        : AddrEvent(end)
    {
    }

    const char* name() override { return "/insns"; }

    void* arg() override { return nullptr; }
};

class Instruction : public AddrEvent {
public:
    explicit Instruction(uintptr_t addr)
        : AddrEvent(addr)
    {
    }

    const char* name() override { return "insn"; }
};

class InstructionDecoded : public AddrEvent {
public:
    explicit InstructionDecoded(uintptr_t start, const std::string& type)
        : AddrEvent(start)
        , _name("/insn type='" + type + "'")
    {
    }

    const char* name() override { return _name.c_str(); }

private:
    std::string _name;
};

class EventStream {
public:
    EventStream(event_callback_t _event_callback, void* _event_stream)
        : event_callback(_event_callback)
        , event_stream(_event_stream)
    {
    }

    void* emit(Event& event);

private:
    event_callback_t event_callback;
    void* event_stream;
};

#endif // CAPSTONE_HSDIS_EVENTSTREAM_H
