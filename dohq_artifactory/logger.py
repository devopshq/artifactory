import logging

# set logger to be configurable from external
logger = logging.getLogger("artifactory")
# Set default logging handler to avoid "No handler found" warnings.
logger.addHandler(logging.NullHandler())
