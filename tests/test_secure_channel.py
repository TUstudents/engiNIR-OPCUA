from enginir_opcua import ua
from enginir_opcua.common.connection import SecureChannel, TransportLimits
from enginir_opcua.crypto.security_policies import SecurityPolicyNone


def test_srv25_channel_exposes_its_security_properties() -> None:
    """Part 6, 6.7.7: sessions read the channel's identity from the channel, not from the policy object."""
    channel = SecureChannel(SecurityPolicyNone(), TransportLimits())
    channel.security_token.ChannelId = 7
    assert channel.channel_id == 7
    assert channel.policy_uri == SecurityPolicyNone.URI
    assert channel.security_mode == ua.MessageSecurityMode.None_
    assert not channel.peer_certificate
    assert not channel.local_certificate
    assert channel.last_used > 0
