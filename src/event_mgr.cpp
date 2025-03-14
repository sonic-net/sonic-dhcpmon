#include "event_mgr.h"

/**
 * @code event_mgr(const std::string& name);
 * 
 * @brief constructor func of event_mgr
 * 
 * @param name     customized name of current mgr
 * 
 */
event_mgr::event_mgr(const std::string& name) {
    this->base = NULL;
    this->name = name;
}

/**
 * @code init_base();
 * 
 * @brief Initialize event base
 */
int event_mgr::init_base() {
    if (this->base != NULL) {
        syslog(LOG_WARNING, "event_mgr: Event base of %s has been initialized\n", this->name.c_str());
        return 0;
    }
    this->base = event_base_new();
    if (this->base == NULL) {
        syslog(LOG_ERR, "evnet_mgr: Could not initialize event base for %s\n", this->name.c_str());
        return -1;
    }
    syslog(LOG_INFO, "event_mgr: Event base for %s initialized successfully\n", this->name.c_str());
    return 0;
}

/**
 * @code add_event(struct event* event, const struct timeval *timeout);
 * 
 * @brief Add event for mgr
 * 
 * @param event     event point
 * @param timeout   timeout value
 */
int event_mgr::add_event(struct event* event, const struct timeval *timeout) {
    if (event_add(event, timeout) != 0) {
        syslog(LOG_ERR, "event_mgr: Failed to add event to %s\n", this->name.c_str());
        return -1;
    }
    this->event_set.insert(event);
    syslog(LOG_INFO, "event_mgr: Add event(fd=%d) to %s\n", event_get_fd(event), this->name.c_str());
    return 0;
}

/**
 * @code free();
 * 
 * @brief release event base and events
 */
void event_mgr::free() {
    int count = 0;
    for (auto event : this->event_set) {
        if (event == NULL)
            continue;
        event_del(event);
        event_free(event);
        syslog(LOG_INFO, "event_mgr: Freed event (fd=%d) for %s\n", event_get_fd(event), this->name.c_str());
        count++;
    }
    event_base_free(this->base);
    syslog(LOG_INFO, "event_mgr: Freed event base and %d events for %s\n", count, this->name.c_str());
}

/**
 * @code get_base();
 * 
 * @brief fetch event base point
 * 
 * @return event base point
 */
struct event_base* event_mgr::get_base() {
    return this->base;
}
