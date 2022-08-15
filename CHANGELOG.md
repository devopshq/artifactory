## 0.8.1
 - Fix recursive properties issue #326
 - Remove unnecessary ArtifactorySaaSPath methods #339
 - Complete Python 3.9 and 3.10 support #347
 - Handling int arguments in create_aql_text method #349
 - Fix jwt.exceptions.DecodeError #351

## 0.8.0
- Add Python 3.10 support
- Add a method to get download statistics for a path - `path.download_stats()` (#288)
- Add `path.deploy_by_checksum(...)` method (#27)
- Raises `ArtifactoryException` instead of `requests.HTTPError` (#179)
- Better logging control with `logging.getLogger("artifactory")` (#235)
- Allow "verify" in the configuration to be a certfile (#281)
- Update properties now uses PATCH method (#65)
- Various documentation improvements
- Added `dry run` option to supported methods (#268)
- Copy function first tries to copy by checksum (#162)


## April, 2018
- Add Admin Area object - you can add\update\read\delete user, group, repository, permission

## Feb 22, 2018
- Add `repo` and `path_in_repo` properties
- Add docs about `stat()`

## DevOpsHQ (dohq-artifactory) => Original (Parallels)
Our library `dohq-artifactory` have this diff (unlinke the original)
  - Support [Artifactory AQL](./README.md#artifactory-query-language)
  - Request use `Session` by default
  - Set property operation is more transactional #8
  - We support our library :)

## 0.1.17 (March 12, 2016)
  - installation via pip complains about failed pypandoc

## 0.1.15 (March 12, 2016)
  - Support for custom base URL [#22]

