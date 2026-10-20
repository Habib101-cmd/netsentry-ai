# L'utilisateur choisit un profil, jamais des options libres (SEC-02).
PROFILES: dict[str, list[str]] = {
    "discovery": ["-sn"],
    "standard": ["-sT", "-sV", "--top-ports", "1000"],
    "deep": ["-sV", "-O", "-p", "1-65535"],
}


def build_cmd(profile: str, target: str, host_timeout_s: int = 300) -> list[str]:
    """Retourne une LISTE d'arguments : jamais de chaîne, jamais de shell."""
    if profile not in PROFILES:
        raise ValueError("Profil de scan inconnu")
    return ["nmap", "-n", *PROFILES[profile], "--host-timeout", f"{host_timeout_s}s",
            "-oX", "-", target]
