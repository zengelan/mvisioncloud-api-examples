#! /usr/bin/python3

import json
import os
import random
from datetime import timedelta, datetime

import requests

# Customer credentials
username = "***************"
password = "***************"
env = "https://www.myshn.net"


def pretty(in_obj):
    if not in_obj:
        return "<Nothing>"
    return str(json.dumps(in_obj, indent=2, sort_keys=True, default=str))


def authenticate(session, username, password, env):
    # Authenticate
    url = env + "/neo/neo-auth-service/oauth/token?grant_type=password"
    heads = {
        'x-auth-username': username,
        'x-auth-password': password
    }
    r = session.post(url, headers=heads)
    p = requests.HTTPError
    if r.status_code != 200:
        print("Could not authenticate to reporting API")
        print("Http Error:", p)
        print(r.text)
        exit(0)
    authinfo = r.json()

    heads = {
        'x-access-token': authinfo.get("access_token"),
        'x-refresh-token': authinfo.get("refresh_token"),
        'tenant-id': str(authinfo.get("tenantID")),
        'tenant-name': str(authinfo.get('tenantName')),
        'user-id': str(authinfo.get("userId")),
        'user-email': str(authinfo.get("email")),
        'user-name': str(authinfo.get("user")),
        # 'Authorization': "{} {}".format(authinfo.get("token_type"), authinfo.get("access_token"))   #optional
    }
    return heads


def get_calendar_filter(days):
    now = datetime.utcnow()
    before = now - timedelta(days=days)
    # date format for the filter is "2020-05-08T00:00:00.000+00:00"
    now_ts = now.strftime("%Y-%m-%dT23:59:59.000+00:00")
    before_ts = before.strftime("%Y-%m-%dT00:00:00.000+00:00")
    datefilter = {
        "type": "between_search_query",
        "field": "created_on_date",
        "lower_bound": before_ts,
        "upper_bound": now_ts
    }
    return datefilter


def get_search_filter(days=30):
    filter = {  # filter template
        "query_request": {
            "sort_dimensions": [{
                "field": "created_on_date",
                "order": "desc"}],
            "pagination": {"offset": 0, "limit": 100},
            "search_query": {
                "type": "and_search_query",
                "queries": [
                    {  # type query: incident is config audit incident
                        "type": "equal_search_query",
                        "value": "audit_violation",
                        "field": "type"
                    }
                ]
            },
            "timezone": "UTC"
        },
        "add_default_filters": False,
        "incident_types": [0, 3, 4, 6, 7]  # static, do not change
    }

    # get date filter
    datefilter = get_calendar_filter(days)

    # append date filter to filters in query
    filter["query_request"]["search_query"]["queries"].append(datefilter)

    print("Filter is now:")
    print(pretty(filter))
    return filter


def get_policy_violations_search(session, tenant_id, filter):
    print("Getting policy violation details for filter")
    myurl = env + "/neo/watchtower/ui/v1/{}/incident/search".format(tenant_id)
    res = session.post(myurl, json=filter)
    if res.status_code != 200:
        print("Could not policy violation details for filter")
        print(res.text)
        return None
    return res.json()


def get_incident_full_details(session, tenant_id, incident_id):
    # Request URL: https://www.myshn.net/neo/watchtower/ui/v1/77231/incident/3:77231:2049:654644892747:434495:ebc1eea16a07a0a919f3df3de69215f1bfbc2218:VERSION_2/note
    inc_url = env + "/neo/watchtower/ui/v1/{}/incident/{}".format(tenant_id, incident_id)
    full_details = session.get(inc_url).json()
    return full_details


def add_note_to_incident(session, tenant_id, incident, user_id, user_email, note):
    # 1 get full details as only those include the number of notes
    full_details = get_incident_full_details(session, tenant_id, incident.get("incident_id"))

    # 2 find how many notes we already have
    has_notes = 0
    if full_details.get("notes_detail"):
        has_notes = full_details.get("notes_detail").get("internal_total")  # we have this number of notes already
    print("We have {} notes on this incident".format(has_notes))

    # 3 create payload
    myurl = env + "/neo/watchtower/ui/v1/{}/incident/{}/note".format(
        tenant_id,
        incident.get("incident_id"))
    print("URL for setting note is {}".format(myurl))
    epoch_now_ms = int(datetime.utcnow().timestamp() * 1000)  # epoch in ms like 1589549137919
    data = {
        "type": "incident_note_request",
        "incident_note": {
            "type": "incident_note",
            "note_id": 0,
            "note": note,
            "user_name": user_email,
            "user_id": int(user_id),
            "user_email": user_email,
            "is_external": False,
            "created_on_date": epoch_now_ms,  # epoch in ms like 1589549137919
            "modified_on_date": epoch_now_ms
        },
        "version": has_notes  # index of the note
    }

    # 4 send payload
    print("Adding the note with index {} to the incident".format(has_notes))
    res = session.post(myurl, json=data)
    if res.status_code != 200:
        print("Could not policy violation details for filter")
        print(res.text)
        return None

    # 5 get full incident details
    inc_url = env + "/neo/watchtower/ui/v1/77231/incident/{}".format(incident.get("incident_id"))
    full_details = session.get(inc_url).json()

    # 6 find how many notes we already have
    has_notes = 0
    if full_details.get("notes_detail"):
        has_notes = full_details.get("notes_detail").get("internal_total")  # we have this number of notes already
    print("We have {} notes on this incident".format(has_notes))


def get_all_incident_statuses(session, tenant_id):
    # url is https://{{fabric}}/neo/watchtower/ui/v1/{{tenant-id}}/workflow-statuses-v2
    url = env + "/neo/watchtower/ui/v1/{}/workflow-statuses-v2".format(tenant_id)
    all_statuses = session.get(url).json()
    print("The available statuses for this tenant are:")
    print(pretty(all_statuses))
    return all_statuses


def set_new_incident_status(session, tenant_id, incident, old_status_id, new_status_id, user_id):
    # 1 create payload
    # url is https://{{fabric}}/neo/v1/{tid}/incident/{id}
    # note: there is also a bulk option for setting status on mutliple incidents:
    # bulk URL: https://www.myshn.net/neo/watchtower/ui/v1/{{tenant-id}}/bulk/incident
    myurl = env + "/neo/watchtower/ui/v1/{}/incident/{}".format(
        tenant_id,
        incident.get("incident_id"))
    print("URL for setting new status is {}".format(myurl))
    data = [{
            "name": "status_id",
            "new_value": str(new_status_id),
            "old_value": str(old_status_id)
        }]
    # 2 send payload via PUT (!)
    print("Setting new incident status to : {}".format(pretty(data)))
    res = session.put(myurl, json=data)
    if res.status_code != 200:
        print("Could not policy violation details for filter")
        print(res.text)
        return None


if __name__ == '__main__':
    print("find incidents and add notes example")

    print("Starting")
    session = requests.session()
    auth_info = authenticate(session, username, password, env)
    # add the required headers to the session and setup variables
    for k, v in auth_info.items():
        if k in ('x-access-token', 'x-refresh-token'):
            session.headers[k] = v
    tenant_id = auth_info['tenant-id']

    # search policy violations
    search_filter = get_search_filter()  # last 30 days by default
    pvs = get_policy_violations_search(session, tenant_id, search_filter)
    print("received {} policy violations/incidents".format(pvs["total"]))

    # chose and pretty print a random incident as sample
    demo_pv = random.choice(pvs["results"])

    print("Picked the incident with the ID '{}' randomly".format(demo_pv.get("incident_id")))
    print(pretty(demo_pv))
    deeplink = "{}/dlp-incidents/#/policy/incidents?isDrilldown=true&incidentId={}".format(env,
                                                                                           demo_pv["workflow"]["id"])
    print("Deeplink to this incident is: {}".format(deeplink))

    # add a note
    user_id = auth_info['user-id']
    user_email = auth_info['user-email']
    note = "This note was added by the script {} and the the incident status will now be set to closed".format(
        os.path.basename(__file__))
    add_note_to_incident(session, tenant_id, demo_pv, user_id, user_email, note)

    # set incident status to closed
    # a) get current status
    old_status = {
        "status": demo_pv.get("workflow").get("status"),
        "status_id": demo_pv.get("workflow").get("status_id")
    }
    print("Current incident status is:")
    print(pretty(old_status))
    # b) get all possible status options in this tenant, incl custom statuses
    all_statuses = get_all_incident_statuses(session, tenant_id)
    # c) pick a random choice of new status
    new_status = random.choice(list(all_statuses.keys()))
    print("Going to set the new incident status (randomly) to '{}'".format(new_status))
    # d) set the new status
    set_new_incident_status(session, tenant_id, demo_pv, old_status['status_id'], all_statuses.get(new_status), user_id)

    # print info
    print("Now the incident looks like this:")
    modified_pv = get_incident_full_details(session, tenant_id, demo_pv.get("incident_id"))
    print(pretty(modified_pv))
    print("Check using the following deeplink: {}".format(deeplink))

    print("End")
