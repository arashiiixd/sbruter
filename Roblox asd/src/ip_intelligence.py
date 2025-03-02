from primp import Client

class IpIntelligence:
    def __init__(self, session: Client) -> None:
        self.session = session

    def get_accept_language(self) -> str:
        try:

            accept_language = "en-US,en;q=0.9"
                
            return accept_language
            
        except:
            raise ValueError("Failed to get proxy / IP information")