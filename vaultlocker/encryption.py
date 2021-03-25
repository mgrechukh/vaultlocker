import gnupg
import requests
import tempfile
import logging

logger = logging.getLogger(__name__)

def encrypt(data, keybase_ids):
    with tempfile.TemporaryDirectory() as tmpdirname: 
        gpg = gnupg.GPG(gnupghome = tmpdirname)
        fingerprints = []
        for k in keybase_ids:
            logger.info("reading from keybase public key {}".format(k))
            result = requests.get("https://keybase.io/{}/key.asc".format(k))
            result.raise_for_status()
            import_result  = gpg.import_keys(result.text)
            if not import_result.fingerprints:
                raise Exception("Error importing {} from keybase: {}".format(k, import_result.results))
            fingerprints += import_result.fingerprints
        logger.info("{} keys processed".format(len(fingerprints)))
        encrypted_ascii_data = gpg.encrypt(data, fingerprints, always_trust = True)
        if encrypted_ascii_data.ok:
            return encrypted_ascii_data.data
        else:
            raise Exception("gpg error: {}".format(data.status))
