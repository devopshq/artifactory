## 0.8.4
- stat: add .created, .last_updated, .last_modified to returned namedtuple #382
- Add federated repo #399

## 0.8.3
- fix: add callable check to progress_bar #379

## 0.8.2
- Support python 3.11 #376
- fix writeto progress_func: the last chunk #375
- Add support for "targetTag" variable of Docker Build promotion API #370
- Bugfix: JSONDecodeError handling for simplejson #354
- Bugfix: Build Promotion works #334
- fix docker_api_version of repo #333
- update default_config_path on windows #362 
- Bugfix: get build runs failed with an exception #366

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
`dohq-artifactory` library has this diff (unlike the original)
  - Support [Artifactory AQL](./README.md#artifactory-query-language)
  - Request use `Session` by default
  - Set property operation is more transactional #8
  - We support our library :)

## 0.1.17 (March 12, 2016)
  - installation via pip complains about failed pypandoc

## 0.1.15 (March 12, 2016)
  - Support for custom base URL [#22]

