"""Analysis skills — one module per Wazuh decoder/log source.

Public surface::

    from skills.analysis.windows_ip_lookup import WindowsIPLookupSkill
    from skills.analysis.windows_username_lookup import WindowsUsernameLookupSkill
    from skills.analysis.windows_rule_lookup import WindowsRuleLookupSkill

Decoder → skill mapping (expand as the lab grows):

    windows_eventchannel  →  WindowsIPLookupSkill
                             WindowsUsernameLookupSkill
                             WindowsRuleLookupSkill
"""

from skills.analysis.windows_ip_lookup import WindowsIPLookupSkill
from skills.analysis.windows_username_lookup import WindowsUsernameLookupSkill
from skills.analysis.windows_rule_lookup import WindowsRuleLookupSkill

__all__ = [
    "WindowsIPLookupSkill",
    "WindowsUsernameLookupSkill",
    "WindowsRuleLookupSkill",
]
