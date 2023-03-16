#!/usr/bin/env python

import sys
import os
import requests as req
import json
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)
import splunk.entity as entity

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)


@Configuration()
class cssmokeCommand(StreamingCommand):

    """%(synopsis)

    ##Syntax

    %(syntax)

    ##Description

    %(description)

    """

    ipfield = Option(
        doc="""
        **Syntax:** **ipfield=***<fieldname>*
        **Description:** Name of the IP address field to look up""",
        require=True,
        validate=validators.Fieldname(),
    )

    def stream(self, events):
        # Load config with user specified API key, if this file does not exist copy it from ../default
        # with open("../default/config.json") as config_file:
        #     data = json.load(config_file)
        #     api_key = data["cssmoke"][0]["api_key"]
        try:
            sessionKey = sys.stdin.readline().strip()
            print(sessionKey)
        except Exception as e:
            raise Exception("Could not get sessionKey {}".format(e))
        myapp = "cssmoke"

        try:
            entities = entity.getEntities(
                ["storage", "passwords"],
                namespace=myapp,
                owner="nobody",
                sessionKey=sessionKey,
            )
        except Exception as e:
            raise Exception("Could not get %s credentials from splunk. Error: %s"
                      % (myapp, str(e)))

        for i, c in entities.items():
            username, api_key = c["username"], c["clear_password"]

        # raise Exception("No credentials have been found")

        if len(sessionKey == 0):
            sys.stderr.write(
                "Did not receive a session key from splunkd. "
                + "Please enable passAuth in inputs.conf for this "
                + "script\n"
            )
            exit()

        # API required headers
        headers = {
            "x-api-key": api_key,
            "Accept": "application/json",
        }

        for event in events:
            event_dest_ip = event[self.ipfield]
            # API required parameters
            params = (
                ("ipAddress", event_dest_ip),
                ("maxAgeInDays", "90"),
                ("verbose", ""),
            )
            # Make API Request
            error = 0
            response = req.get(
                f"https://cti.api.crowdsec.net/v2/smoke/{event_dest_ip}",
                headers=headers,
                params=params,
            )
            if response.status_code == 200:
                data = response.json()

                ip_range_score = data["ip_range_score"]
                ip = data["ip"]
                ip_range = data["ip_range"]
                as_name = data["as_name"]
                as_num = data["as_num"]

                country = data["location"]["country"]
                city = data["location"]["city"]
                latitude = data["location"]["latitude"]
                longitude = data["location"]["longitude"]
                reverse_dns = data["reverse_dns"]

                behaviors = data["behaviors"]

                first_seen = data["history"]["first_seen"]
                last_seen = data["history"]["last_seen"]
                full_age = data["history"]["full_age"]
                days_age = data["history"]["days_age"]

                false_positives = data["classifications"]["false_positives"]
                classifications = data["classifications"]["classifications"]

                # attack_details
                attack_details = data["attack_details"]

                # target_countries
                target_countries = data["target_countries"]

                # background_noise_score
                background_noise_score = data["background_noise_score"]

                # overall
                overall_aggresiveness = data["scores"]["overall"]["aggressiveness"]
                overall_threat = data["scores"]["overall"]["threat"]
                overall_trust = data["scores"]["overall"]["trust"]
                overall_anomaly = data["scores"]["overall"]["anomaly"]
                overall_total = data["scores"]["overall"]["total"]

                # last_day
                last_day_aggresiveness = data["scores"]["last_day"]["aggressiveness"]
                last_day_threat = data["scores"]["last_day"]["threat"]
                last_day_trust = data["scores"]["last_day"]["trust"]
                last_day_anomaly = data["scores"]["last_day"]["anomaly"]
                last_day_total = data["scores"]["last_day"]["total"]

                # last_week
                last_week_aggressiveness = data["scores"]["last_week"]["aggressiveness"]
                last_week_threat = data["scores"]["last_week"]["threat"]
                last_week_trust = data["scores"]["last_week"]["trust"]
                last_week_anomaly = data["scores"]["last_week"]["anomaly"]
                last_week_total = data["scores"]["last_week"]["total"]

                # last_month
                last_month_aggressiveness = data["scores"]["last_month"][
                    "aggressiveness"
                ]
                last_month_threat = data["scores"]["last_month"]["threat"]
                last_month_trust = data["scores"]["last_month"]["trust"]
                last_month_anomaly = data["scores"]["last_month"]["anomaly"]
                last_month_total = data["scores"]["last_month"]["total"]

                # references
                references = data["references"]

            else:
                error = 1
                event["ApiError"] = "Invalid Request:status_code=" + str(
                    response.status_code
                )

            # Set event values to be returned
            if error == 0:
                event["ip_range_score"] = ip_range_score
                event["ip"] = ip
                event["ip_range"] = ip_range
                event["as_name"] = as_name
                event["as_num"] = as_num

                event["country"] = country
                event["city"] = city
                event["latitude"] = latitude
                event["longitude"] = longitude

                event["reverse_dns"] = reverse_dns

                event["behaviors"] = behaviors

                event["first_seen"] = first_seen
                event["last_seen"] = last_seen
                event["full_age"] = full_age
                event["days_age"] = days_age

                event["false_positives"] = false_positives
                event["classifications"] = classifications

                # attack_details
                event["attack_details"] = attack_details

                # target_countries
                event["target_countries"] = target_countries

                # background_noise_score
                event["background_noise_score"] = background_noise_score

                # scores
                event["overall_aggresiveness"] = overall_aggresiveness
                event["overall_threat"] = overall_threat
                event["overall_trust"] = overall_trust
                event["overall_anomaly"] = overall_anomaly
                event["overall_total"] = overall_total

                event["last_day_aggresiveness"] = last_day_aggresiveness
                event["last_day_threat"] = last_day_threat
                event["last_day_trust"] = last_day_trust
                event["last_day_anomaly"] = last_day_anomaly
                event["last_day_total"] = last_day_total

                event["last_week_aggressiveness"] = last_week_aggressiveness
                event["last_week_threat"] = last_week_threat
                event["last_week_trust"] = last_week_trust
                event["last_week_anomaly"] = last_week_anomaly
                event["last_week_total"] = last_week_total

                event["last_month_aggressiveness"] = last_month_aggressiveness
                event["last_month_threat"] = last_month_threat
                event["last_month_trust"] = last_month_trust
                event["last_month_anomaly"] = last_month_anomaly
                event["last_month_total"] = last_month_total

                event["references"] = references

            # Finalize event
            yield event


dispatch(cssmokeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
