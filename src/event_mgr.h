#ifndef EVENT_MGR_H
#define EVENT_MGR_H

#include <event2/event.h>
#include <string>
#include <unordered_map>
#include <unordered_set>

class event_mgr {
    public:
        event_mgr(const std::string& name);
        int init_base();
        int add_event(struct event* event, const struct timeval *timeout, const std::string &tag="");
        void del_all_events(const std::string &tag="");
        void activate_all_events(const std::string &tag="", int res=0);
        void free();
        struct event_base* get_base();
    private:
        std::string name;
        struct event_base *base;
        std::unordered_map<std::string, std::unordered_set<struct event*>> event_map;
};

#endif // EVENT_MGR_H
