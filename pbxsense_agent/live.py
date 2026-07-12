from __future__ import annotations


def home_live_events(previous: dict, current: dict) -> list[dict]:
    events: list[dict] = []

    if previous.get("connection") != current.get("connection"):
        events.append(
            {"type": "connection_updated", "data": current.get("connection", {})}
        )

    if previous.get("now") != current.get("now"):
        events.append({"type": "call_updated", "data": current.get("now", {})})

    events.extend(
        _collection_events(
            previous.get("signals", []),
            current.get("signals", []),
            key="id",
            created_type="signal_created",
            updated_type="signal_updated",
        )
    )
    events.extend(
        _removed_collection_events(
            previous.get("signals", []),
            current.get("signals", []),
            key="id",
            removed_type="signal_removed",
        )
    )

    if previous.get("calls") != current.get("calls"):
        events.append({"type": "calls_updated", "data": current.get("calls", [])})

    events.extend(
        _collection_events(
            previous.get("people", []),
            current.get("people", []),
            key="extension",
            created_type="person_updated",
            updated_type="person_updated",
        )
    )

    events.extend(
        _collection_events(
            previous.get("trunks", []),
            current.get("trunks", []),
            key="endpoint",
            created_type="trunk_updated",
            updated_type="trunk_updated",
        )
    )

    events.extend(
        _collection_events(
            previous.get("queues", []),
            current.get("queues", []),
            key="queue",
            created_type="queue_updated",
            updated_type="queue_updated",
        )
    )

    return events


def _collection_events(
    previous_items: object,
    current_items: object,
    *,
    key: str,
    created_type: str,
    updated_type: str,
) -> list[dict]:
    if not isinstance(previous_items, list) or not isinstance(current_items, list):
        return []

    previous_by_key = {
        str(item.get(key, "")): item
        for item in previous_items
        if isinstance(item, dict) and item.get(key)
    }
    events: list[dict] = []

    for item in current_items:
        if not isinstance(item, dict):
            continue
        item_key = str(item.get(key, ""))
        if not item_key:
            continue
        previous_item = previous_by_key.get(item_key)
        if previous_item is None:
            events.append({"type": created_type, "data": item})
        elif previous_item != item:
            events.append({"type": updated_type, "data": item})

    return events


def _removed_collection_events(
    previous_items: object,
    current_items: object,
    *,
    key: str,
    removed_type: str,
) -> list[dict]:
    if not isinstance(previous_items, list) or not isinstance(current_items, list):
        return []

    current_keys = {
        str(item.get(key, ""))
        for item in current_items
        if isinstance(item, dict) and item.get(key)
    }
    return [
        {"type": removed_type, "data": {key: item_key}}
        for item_key in (
            str(item.get(key, ""))
            for item in previous_items
            if isinstance(item, dict) and item.get(key)
        )
        if item_key not in current_keys
    ]
