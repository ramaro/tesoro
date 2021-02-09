import logging
import re
from base64 import b64decode, b64encode

from kapitan.refs.base import REF_TOKEN_TAG_PATTERN
from tesoro import REF_CONTROLLER


logger = logging.getLogger(__name__)


def prepare_obj(req_uid, req_obj):
    """
    updates object and returns transformation operations
    on specific object kinds to perform post reveal
    """
    transformations = {}
    obj_kind = req_obj["kind"]
    if obj_kind == "Secret":
        secret_name = req_obj["metadata"]["name"]
        transformations["Secret"] = {"data": {}}
        for item_name, item_value in req_obj["data"].items():
            decoded_item = b64decode(item_value).decode()

            valid_refs = re.finditer(REF_TOKEN_TAG_PATTERN, decoded_item)
            if not valid_refs:
                continue  # this has no refs, do nothing
            else:
                logger.debug(
                    'message="Secret transformation", request_uid=%s, secret_name=%s, decoded_item=%s',
                    req_uid,
                    secret_name,
                    decoded_item,
                )
                # each decoded_item can have multiple refs
                # peek and register first ref
                for ref in valid_refs:
                    ref = ref.groups()[0]
                    ref_obj = REF_CONTROLLER[ref]
                    # honor first ref encoding
                    # a Secret can't have multiple encodings
                    transformations["Secret"]["data"][item_name] = {"encoding": ref_obj.encoding}
                    break
                # override with decoded ref so we can reveal
                req_obj["data"][item_name] = decoded_item

    return transformations


def transform_obj(req_obj, transformations):
    "updates req_obj with transformations"
    secret_tranformations = transformations.get("Secret", {})
    secret_data_items = secret_tranformations.get("data", {}).items()
    for item_name, transform in secret_data_items:
        encoding = transform.get("encoding", None)
        if encoding == "original":
            item_value_encoded = b64encode(req_obj["data"][item_name].encode()).decode()
            req_obj["data"][item_name] = item_value_encoded
