#include <syslog.h>

#include "event_mgr.h"

/**
 * @code event_mgr(const std::string& name);
 * 
 * @brief constructor func of event_mgr
 * 
 * @param name     customized name of current mgr
 * 
 */
event_mgr::event_mgr(const std::string& name)
{
    syslog(LOG_INFO, "event_mgr: Create event manager %s", name.c_str());
    this->base = NULL;
    this->name = name;
}

/**
 * @code init_base();
 * 
 * @brief Initialize event base
 */
int event_mgr::init_base()
{
    if (this->base != NULL) {
        syslog(LOG_ALERT, "event_mgr: Event base of %s has been initialized", this->name.c_str());
        return 0;
    }
    this->base = event_base_new();
    if (this->base == NULL) {
        syslog(LOG_ALERT, "event_mgr: Could not initialize event base for %s", this->name.c_str());
        return -1;
    }
    syslog(LOG_INFO, "event_mgr: Event base for %s initialized successfully", this->name.c_str());
    return 0;
}

/**
 * @code add_event(event, timeout, tag);
 * 
 * @brief add event to event base with optional timeout and tag
 * @param event     pointer to event struct
 * @param timeout   pointer to timeval struct for timeout, NULL if no timeout
 * @param tag       tag string for grouping events
 * @return 0 on success, otherwise for failure
 */
int event_mgr::add_event(struct event* event, const struct timeval *timeout, const std::string &tag)
{
    if (event_add(event, timeout) < 0) {
        syslog(LOG_ALERT, "event_mgr: Failed to add event to %s", this->name.c_str());
        return -1;
    }
    this->event_map[""].insert(event);
    if (tag != "") {
        this->event_map[tag].insert(event);
    }
    syslog(LOG_INFO, "event_mgr: Add event(fd=%d) with tag %s to %s", event_get_fd(event), tag.c_str(), this->name.c_str());
    return 0;
}

/**
 * @code del_all_events(tag);
 * 
 * @brief delete all events with optional tag
 * @param tag       tag string for grouping events
 */
void event_mgr::del_all_events(const std::string &tag)
{
    int count = 0;
    for (const auto &event : this->event_map[tag]) {
        event_del(event);
        event_free(event);
        count++;
        syslog(LOG_INFO, "event_mgr: Deleted event (fd=%d) of tag %s from %s", event_get_fd(event), tag.c_str(), this->name.c_str());
    }
    if (tag != "") {
        std::unordered_set<struct event *> &tagless_set = this->event_map[""];
        std::unordered_set<struct event *> &tagged_set = this->event_map[tag];
        for (const auto &event : tagged_set) {
            tagless_set.erase(event);
        }
        this->event_map.erase(tag);
    } else {
        this->event_map.clear();
    }
    syslog(LOG_INFO, "event_mgr: Deleted %d events of tag %s for %s", count, tag.c_str(), this->name.c_str());
}

/**
 * @code activate_all_events(tag, res);
 * 
 * @brief activate all events with optional tag
 * @param tag       tag string for grouping events
 * @param res       result code to be passed to event_active
 */
void event_mgr::activate_all_events(const std::string &tag, int res)
{
    for (const auto &event : this->event_map[tag]) {
        event_active(event, res, 0);
        syslog(LOG_INFO, "event_mgr: Activated event (fd=%d) of tag %s from %s", event_get_fd(event), tag.c_str(), this->name.c_str());
    }
}

/**
 * @code free();
 * 
 * @brief release event base and events
 */
void event_mgr::free()
{
    this->del_all_events();
    event_base_free(this->base);
    syslog(LOG_INFO, "event_mgr: Freed event base for %s", this->name.c_str());
}

/**
 * @code get_base();
 * 
 * @brief fetch event base point
 * 
 * @return event base point
 */
struct event_base* event_mgr::get_base()
{
    return this->base;
}