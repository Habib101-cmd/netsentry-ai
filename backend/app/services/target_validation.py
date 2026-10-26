import ipaddress

MAX_PREFIX = 22  # taille max d'une cible (/22 = 1024 adresses)
FORBIDDEN = [
    ipaddress.ip_network(n) for n in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4")
]


class TargetError(ValueError):
    pass


def parse_target(target: str) -> ipaddress.IPv4Network:
    target = (target or "").strip()
    if not target or len(target) > 64:
        raise TargetError("Cible invalide")
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise TargetError("Format invalide (adresse IP ou CIDR attendu)")
    if net.version != 4:
        raise TargetError("IPv6 non pris en charge")
    return net


def validate_scope_cidr(cidr: str, allow_public: bool) -> ipaddress.IPv4Network:
    net = parse_target(cidr)
    if any(net.overlaps(f) for f in FORBIDDEN):
        raise TargetError("Plage interdite (loopback, link-local, multicast, réservée)")
    if not net.is_private and not allow_public:
        raise TargetError("Plage publique : autorisation explicite de l'administrateur requise")
    return net


def validate_target(target: str, scopes: list[tuple[int, str, bool]]):
    """scopes : liste de (scope_id, cidr, allow_public). Retourne (réseau, scope_id)."""
    net = parse_target(target)
    if net.prefixlen < MAX_PREFIX:
        raise TargetError(f"Cible trop large (minimum /{MAX_PREFIX})")
    if any(net.overlaps(f) for f in FORBIDDEN):
        raise TargetError("Plage interdite (loopback, link-local, multicast, réservée)")
    for scope_id, cidr, allow_public in scopes:
        if net.subnet_of(ipaddress.ip_network(cidr, strict=False)):
            if not net.is_private and not allow_public:
                raise TargetError("Adresse publique non autorisée")
            return net, scope_id
    raise TargetError("Cible hors périmètre autorisé")
