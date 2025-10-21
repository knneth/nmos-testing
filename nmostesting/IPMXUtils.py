from . import Config as CONFIG


def filter_resources(resources, resource_type):

    if resource_type == "senders":
        try:
            print("#### FILTER senders", CONFIG.senders_guid)
        except Exception as e:
            CONFIG.senders_guid = None
        print("#### FILTER senders", CONFIG.senders_guid)

    if resource_type == "receivers":
        try:
            print("#### FILTER receivers", CONFIG.receivers_guid)
        except Exception as e:
            CONFIG.receivers_guid = None
        print("#### FILTER receivers", CONFIG.receivers_guid)

    if not isinstance(resources, list):
        raise ValueError("invalid use of filter_resources")

    if resource_type not in ("senders", "receivers"):
        return resources

    filtered = []

    if all(isinstance(item, dict) for item in resources):
        for resource in resources:
            if (resource_type == "senders" and CONFIG.senders_guid is not None
                    and resource["id"] not in CONFIG.senders_guid):
                print("skip senders {}".format(resource["id"]))
                continue
            if (resource_type == "receivers" and CONFIG.receivers_guid is not None
                    and resource["id"] not in CONFIG.receivers_guid):
                print("skip receivers {}".format(resource["id"]))
                continue

            print("KEEP {} {}".format(resource_type, resource["id"]))
            filtered.append(resource)
        return filtered

    if all(isinstance(item, str) for item in resources):
        for resource_id in resources:
            resource_id = resource_id.rstrip("/")  # GET to connection API return trailing '/'
            if (resource_type == "senders" and CONFIG.senders_guid is not None
                    and resource_id not in CONFIG.senders_guid):
                print("skip senders {}".format(resource_id))
                continue
            if (resource_type == "receivers" and CONFIG.receivers_guid is not None
                    and resource_id not in CONFIG.receivers_guid):
                print("skip receivers {}".format(resource_id))
                continue

            print("KEEP {} {}".format(resource_type, resource_id))
            filtered.append(resource_id)
        return filtered

    return filtered
