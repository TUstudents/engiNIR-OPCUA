"""The counters of a Subscription, kept by the subscription code and read by the diagnostics (OPC 10000-5, 12.15)."""

from __future__ import annotations

from dataclasses import dataclass

UINT32_MASK = 0xFFFFFFFF


@dataclass
class SubscriptionCounters:
    modify_count: int = 0
    enable_count: int = 0
    disable_count: int = 0
    republish_request_count: int = 0
    republish_message_count: int = 0
    transfer_request_count: int = 0
    transferred_to_alt_client_count: int = 0
    transferred_to_same_client_count: int = 0
    publish_request_count: int = 0
    data_change_notifications_count: int = 0
    event_notifications_count: int = 0
    late_publish_request_count: int = 0
    keep_alive_entered_count: int = 0
    discarded_message_count: int = 0
    monitoring_queue_overflow_count: int = 0
    event_queue_overflow_count: int = 0
