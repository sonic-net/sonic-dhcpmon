#ifndef EVENT_MGR_H
# define EVENT_MGR_H

#include <event2/event.h>
#include <string>
#include <syslog.h>
#include <unordered_set>

class event_mgr {
    public:
        event_mgr(const std::string& name);
        int init_base();
        int add_event(struct event* event, const struct timeval *timeout);
        void free();
        struct event_base* get_base();
    private:
        std::string name;
        struct event_base *base;
        std::unordered_set<struct event*> event_set;
        std::string _get_event_info(struct event *event);
};

#endif // EVENT_MGR_H
