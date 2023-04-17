# Python interface library for JFrog Artifactory ![](https://img.shields.io/badge/status-supported-green.svg)


[![docs](https://img.shields.io/readthedocs/pip.svg)][1]
[![dohq-artifactory build Status](https://github.com/devopshq/artifactory/workflows/CI/badge.svg?branch=master)][2]
[![dohq-artifactory on PyPI](https://img.shields.io/pypi/v/dohq-artifactory.svg)][3] 
[![dohq-artifactory license](https://img.shields.io/pypi/l/dohq-artifactory.svg)][4]

`dohq-artifactory` is a live python package for [JFrog Artifactory][5]. This module is intended to serve as a logical 
descendant of [pathlib][6], and it implements everything as closely as 
possible to the origin with few exceptions. Current module was forked from outdated 
[parallels/artifactory][7] and supports all functionality from the original 
package.

[1]: https://devopshq.github.io/artifactory/
[2]: https://github.com/devopshq/artifactory/actions/workflows/ci.yml
[3]: https://pypi.python.org/pypi/dohq-artifactory
[4]: https://github.com/devopshq/artifactory/blob/master/LICENSE
[5]: https://www.jfrog.com/confluence/display/JFROG/JFrog+Artifactory
[6]: https://docs.python.org/3/library/pathlib.html
[7]: https://github.com/parallels/artifactory

# Tables of Contents

<!-- toc -->

- [Install](#install)
- [Usage](#usage)
  * [Authentication](#authentication)
  * [Artifactory SaaS](#artifactory-saas)
  * [Walking Directory Tree](#walking-directory-tree)
  * [Downloading Artifacts](#downloading-artifacts)
  * [Downloading Artifacts in chunks](#downloading-artifacts-in-chunks)
  * [Downloading Artifacts folder as archive](#downloading-artifacts-folder-as-archive)
  * [Uploading Artifacts](#uploading-artifacts)
  * [Copy Artifacts](#copy-artifacts)
  * [Move Artifacts](#move-artifacts)
  * [Remove Artifacts](#remove-artifacts)
  * [Artifact properties](#artifact-properties)
  * [Repository Scheduled Replication Status](#repository-scheduled-replication-status)
  * [Artifactory Query Language](#artifactory-query-language)
  * [Artifact Stat](#artifact-stat)
    + [File/Folder Statistics](#filefolder-statistics)
    + [Get Download Statistics](#get-download-statistics)
  * [Promote Docker image](#promote-docker-image)
  * [Builds](#builds)
  * [Exception handling](#exception-handling)
- [Admin area](#admin-area)
  * [User](#user)
    + [API Keys](#api-keys)
  * [Group](#group)
    + [Internal](#internal)
    + [GroupLDAP](#groupldap)
  * [RepositoryLocal](#repositorylocal)
  * [RepositoryVirtual](#repositoryvirtual)
  * [RepositoryRemote](#repositoryremote)
  * [Project](#project)
  * [Get repository of any type](#get-repository-of-any-type)
  * [Iterate over repository artifacts](#iterate-over-repository-artifacts)
  * [Access repository child item](#access-repository-child-item)
  * [Search for certain package artifacts](#search-for-certain-package-artifacts)
  * [PermissionTarget](#permissiontarget)
  * [Token](#token)
  * [Common](#common)
- [Advanced](#advanced)
  * [Session](#session)
  * [SSL Cert Verification Options](#ssl-cert-verification-options)
  * [Timeout on requests](#timeout-on-requests)
  * [Logging](#logging)
  * [Global Configuration File](#global-configuration-file)
- [Contribute](#contribute)
- [Advertising](#advertising)

<!-- tocstop -->

# Install #
Upgrade/install to the newest available version:
```bash
pip install dohq-artifactory --upgrade
```
Install latest development version (Warning! It may contains some errors!):
```bash
pip install dohq-artifactory --upgrade --pre
```
Or specify version, e.g.:
```bash
pip install dohq-artifactory==0.5.dev243
```

# Usage
## Authentication ##

`dohq-artifactory` supports these ways of authentication:

- Username and password (or [API KEY](https://www.jfrog.com/confluence/display/RTF/Updating+Your+Profile#UpdatingYourProfile-APIKey)) to access restricted resources, you can pass ```auth``` parameter to ArtifactoryPath.
- [API KEY](https://www.jfrog.com/confluence/display/RTF/Updating+Your+Profile#UpdatingYourProfile-APIKey) can pass with `apikey` parameter.
- [Access Token](https://www.jfrog.com/confluence/display/JFROG/Access+Tokens#AccessTokens-UsingTokens) can pass with `token` parameter.

```python
from artifactory import ArtifactoryPath

# API_KEY
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/restricted-path", apikey="MY_API_KEY"
)

# Access Token
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/restricted-path", token="MY_ACCESS_TOKEN"
)

# User and password OR API_KEY
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/restricted-path",
    auth=("USERNAME", "PASSWORD or API_KEY"),
)

# Other authentication types
from requests.auth import HTTPDigestAuth

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/restricted-path",
    auth=("USERNAME", "PASSWORD"),
    auth_type=HTTPDigestAuth,
)

from requests.auth import HTTPBasicAuth

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/restricted-path",
    auth=("USERNAME", "PASSWORD"),
    auth_type=HTTPBasicAuth,
)

# Load username, password from global config if exist:
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/restricted-path",
    auth_type=HTTPBasicAuth,
)

path.touch()
```

## Artifactory SaaS
If you use Artifactory SaaS solution - use `ArtifactorySaaSPath` class.  
SaaS supports all methods and authentication types as `ArtifactoryPath`. We have to use other class, because as a SaaS 
service, the URL is different from an on-prem installation and the REST API endpoints.
```python
from artifactory import ArtifactorySaaSPath

path = ArtifactorySaaSPath(
    "https://myartifactorysaas.jfrog.io/myartifactorysaas/folder/path.xml",
    apikey="MY_API_KEY",
)
```


## Walking Directory Tree ##

Get directory listing:

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath("http://repo.jfrog.org/artifactory/gradle-ivy-local")
for p in path:
    print(p)
```

Find all `.gz` files in current dir, recursively:

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath("http://repo.jfrog.org/artifactory/distributions/org/")

for p in path.glob("**/*.gz"):
    print(p)
```

## Downloading Artifacts ##

Download artifact to a local filesystem:

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz"
)

with path.open() as fd, open("tomcat.tar.gz", "wb") as out:
    out.write(fd.read())
```

## Downloading Artifacts in chunks ##

Download artifact to the local filesystem using chunks (in bytes) to prevent loading the entire response into memory at once.
This can help with getting big files or resolve [known issue](https://github.com/devopshq/artifactory/issues/135)

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz"
)

# download by providing path to out file and use default chunk 1024
path.writeto(out="tomcat.tar.gz")

# download and suppress progress messages
path.writeto(out="tomcat2.tar.gz", progress_func=None)

# download by providing out as file object and specify chunk size
with open("tomcat3.tar.gz", "wb") as out:
    path.writeto(out, chunk_size=256)


# download and use custom print function
def custom_print(bytes_now, total, custom):
    """
    Custom function that accepts first two arguments as [int, int] in its signature
    """
    print(bytes_now, total, custom)


# since writeto requires [int, int] in its signature, all custom arguments you have to provide via lambda function or
# similar methods
path.writeto(
    out="tomcat5.tar.gz",
    progress_func=lambda x, y: custom_print(x, y, custom="test"),
)
```


## Downloading Artifacts folder as archive ##
Download artifact folder to a local filesystem as archive (supports zip/tar/tar.gz/tgz)
Allows to specify archive type and request checksum for the folder

Note: Archiving should be enabled on the server!
```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my_url:8080/artifactory/my_repo/winx64/aas", auth=("user", "password")
)

with path.archive(archive_type="zip", check_sum=False).open() as archive:
    with open(r"D:\target.zip", "wb") as out:
        out.write(archive.read())

# download folder archive in chunks
path.archive().writeto(out="my.zip", chunk_size=100 * 1024)
```

## Uploading Artifacts ##

Deploy a regular file ```myapp-1.0.tar.gz```. This method by default will calculate all available checksums and attach
them to the file

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0"
)
path.mkdir()

path.deploy_file("./myapp-1.0.tar.gz")
```

Deploy artifacts from archive: this will automatically extract the contents of the archive on the server preserving 
the archive's paths

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0"
)
path.mkdir()

path.deploy_file("./myapp-1.0.tar.gz", explode_archive=True)
```

Atomically deploy artifacts from archive: this will automatically extract the contents of the archive on the server 
preserving the archive's paths. This is primarily useful when you want Artifactory to see all the artifacts at once, 
e.g., for indexing purposes.

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0"
)
path.mkdir()

path.deploy_file(
    "./myapp-1.0.tar.gz", explode_archive=True, explode_archive_atomic=True
)
```

[Deploy artifact by checksum](https://www.jfrog.com/confluence/display/RTF6X/Artifactory+REST+API#ArtifactoryRESTAPI-DeployArtifactbyChecksum): deploy an artifact to the specified destination by checking if the artifact
content already exists in Artifactory. If Artifactory already contains a user
readable artifact with the same checksum the artifact content is copied over to
the new location without requiring content transfer.

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath("http://my-artifactory/artifactory/my_repo/foo")
sha1 = "1be5d2dbe52ddee96ef2d17d354e2be0a155a951"
sha256 = "00bbf80ccca376893d60183e1a714e707fd929aea3e458f9ffda60f7ae75cc51"

# If you don't know sha value, you can calculate it via
# sha1 = artifactory.sha1sum("local_path_of_your_file")
# or
# sha256 = artifactory.sha256sum("local_path_of_your_file")

# Each of the following 4 methods works fine if the artifact content already
# exists in Artifactory.
path.deploy_by_checksum(sha1=sha1)

# deploy by sha1 via checksum parameter
path.deploy_by_checksum(checksum=sha1)

# deploy by sha256 via sha256 parameter
path.deploy_by_checksum(sha256=sha256)

# deploy by sha256 via checksum parameter
path.deploy_by_checksum(checksum=sha256)
```

Deploy a debian package ```myapp-1.0.deb``` to an ```existent``` folder

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath("http://my-artifactory/artifactory/ubuntu-local/pool/")
path.deploy_deb(
    "./myapp-1.0.deb", distribution="trusty", component="main", architecture="amd64"
)
```

Deploy a debian package ```myapp-1.0.deb``` to a ```non-existent``` folder

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/ubuntu-local/pool/myapp-1.0.deb"
)
path.deploy_deb(
    "./myapp-1.0.deb", distribution="trusty", component="main", architecture="amd64"
)

# if you want to set multiple values you can use list to set them
path.deploy_deb(
    "./myapp-1.0.deb",
    distribution=["dist1", "dist2"],
    component="main",
    architecture=["amd64", "i386"],
)
```

## Copy Artifacts
Copy artifact from this path to destination.
If files are on the same instance of artifactory, lightweight (local)
copying will be attempted.

The suppress_layouts parameter, when set to `True`, will allow artifacts
from one path to be copied directly into another path without enforcing
repository layouts. The default behaviour is to copy to the repository
root, but remap the [org], [module], [baseVer], etc. structure to the
target repository.

For example, we have a builds repository using the default maven2
repository where we publish our builds, and we also have a published
repository where a directory for production and a directory for
staging environments should hold the current promoted builds. How do
we copy the contents of a build over to the production folder?

```python
from artifactory import ArtifactoryPath

source = ArtifactoryPath("http://example.com/artifactory/builds/product/product/1.0.0/")
dest = ArtifactoryPath("http://example.com/artifactory/published/production/")

"""
Using copy with the default, suppress_layouts=False, the artifacts inside
builds/product/product/1.0.0/ will not end up in the published/production
path as we intended, but rather the entire structure product/product/1.0.0
is placed in the destination repo.
"""

source.copy(dest)
for p in dest:
    print(p)
# http://example.com/artifactory/published/production/foo-0.0.1.gz
# http://example.com/artifactory/published/production/foo-0.0.1.pom

for p in ArtifactoryPath(
    "http://example.com/artifactory/published/product/product/1.0.0.tar"
):
    print(p)
# http://example.com/artifactory/published/product/product/1.0.0/product-1.0.0.tar.gz
# http://example.com/artifactory/published/product/product/1.0.0/product-1.0.0.tar.pom

"""
Using copy with suppress_layouts=True, the contents inside our source are copied
directly inside our dest as we intended.
"""

source.copy(dest, suppress_layouts=True)
for p in dest:
    print(p)
"""
http://example.com/artifactory/published/production/foo-0.0.1.gz
http://example.com/artifactory/published/production/foo-0.0.1.pom
http://example.com/artifactory/published/production/product-1.0.0.tar.gz
http://example.com/artifactory/published/production/product-1.0.0.tar.pom
"""

# you can use dry run just to check if command will succeed without real change, adds debug message
source.copy(dest, dry_run=True)
```

## Move Artifacts
Move artifact from this path to destination.

The suppress_layouts parameter, when set to `True`, will allow artifacts
from one path to be copied directly into another path without enforcing
repository layouts. The default behaviour is to copy to the repository
root, but remap the [org], [module], [baseVer], etc. structure to the
target repository.

```python
from artifactory import ArtifactoryPath

source = ArtifactoryPath("http://example.com/artifactory/builds/product/product/1.0.0/")
dest = ArtifactoryPath("http://example.com/artifactory/published/production/")

source.move(dest)

# you can use dry run just to check if command will succeed without real change, adds debug message
source.move(dest, dry_run=True)
```

## Remove Artifacts
```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz"
)

if path.exists():
    path.unlink()
```

## Artifact properties ##
You can get and set (or remove) properties from artifact.
Following example shows how to manage properties and property sets
```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz"
)

# Get properties
properties = path.properties
print(properties)

# Update a property or add if does not exist
properties["qa"] = "tested"
path.properties = properties

# add/replace set of properties
new_props = {
    "test": ["test_property"],
    "time": ["2018-01-16 12:17:44.135143"],
    "addthis": ["addthis"],
}
path.properties = new_props

# Remove properties
properties.pop("release")
path.properties = properties
```

## Repository Scheduled Replication Status ##
Returns the status of scheduled  cron-based replication jobs define via the Artifactory UI on repositories.
Supported by local, local-cached and remote repositories.

Notes: Requires Artifactory Pro

Security: Requires a user with 'read' permission (can be anonymous)
```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "https://repo.jfrog.org/artifactory/repo1-cache/archetype-catalog.xml"
)

rep_status = path.replication_status
print("status: ", rep_status["status"])
```

## Artifactory Query Language
You can use [Artifactory Query Language](https://www.jfrog.com/confluence/display/RTF/Artifactory+Query+Language) in python.

```python
from artifactory import ArtifactoryPath

arti_path = ArtifactoryPath(
    "http://my-artifactory/artifactory"
)  # path to artifactory, NO repo

# dict support
# Send query:
# items.find({"repo": "myrepo"})
artifacts = arti_path.aql("items.find", {"repo": "myrepo"})

# list support.
# Send query:
# items.find().include("name", "repo")
artifacts = arti_path.aql("items.find()", ".include", ["name", "repo"])

#  support complex query
# Example 1
# items.find(
#     {
#         "$and": [
#             {"repo": {"$eq": "repo"}},
#             {"$or": [{"path": {"$match": "*path1"}}, {"path": {"$match": "*path2"}}]},
#         ]
#     }
# )
aqlargs = [
    "items.find",
    {
        "$and": [
            {"repo": {"$eq": "repo"}},
            {
                "$or": [
                    {"path": {"$match": "*path1"}},
                    {"path": {"$match": "*path2"}},
                ]
            },
        ]
    },
]

# artifacts_list contains raw data (list of dict)
# Send query
artifacts_list = arti_path.aql(*aqlargs)

# Example 2
# The query will find all items in repo docker-prod that are of type file and were created after timecode. The
# query will only display the fields "repo", "path" and "name" and will sort the result ascendingly by those fields.
# items.find(
#     {
#         "$or": [{"repo": "docker-prod"}],
#         "type": "file",
#         "created": {"$gt": "2019-07-10T19:20:30.45+01:00"},
#     }
# ).include("repo", "path", "name",).sort({"$asc": ["repo", "path", "name"]})
aqlargs = [
    "items.find",
    {
        "$and": [
            {"repo": "docker-prod"},
            {"type": "file"},
            {"created": {"$gt": "2019-07-10T19:20:30.45+01:00"}},
        ]
    },
    ".include",
    ["repo", "path", "name"],
    ".sort",
    {"$asc": ["repo", "path", "name"]},
]
artifacts_list = arti_path.aql(*aqlargs)

# You can convert to pathlib object:
artifact_pathlib = map(arti_path.from_aql, artifacts_list)
artifact_pathlib_list = list(map(arti_path.from_aql, artifacts_list))
```


## Artifact Stat
### File/Folder Statistics
You can get hash (`md5`, `sha1`, `sha256`), creator, create date, and change date:

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz"
)

# Get FileStat
stat = path.stat()
print(stat)
print(stat.ctime)
print(stat.mtime)
print(stat.created_by)
print(stat.modified_by)
print(stat.mime_type)
print(stat.size)
print(stat.sha1)
print(stat.sha256)
print(stat.md5)
print(stat.is_dir)
print(stat.children)
print(stat.repo)
```

### Get Download Statistics
Information about number of downloads, user that last downloaded and date of last download
```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz"
)

# Get FileStat
download_stat = path.download_stats()
print(download_stat)
print(download_stat.last_downloaded)
print(download_stat.last_downloaded_by)
print(download_stat.download_count)
print(download_stat.remote_download_count)
print(download_stat.remote_last_downloaded)
print(download_stat.uri)
```

## Promote Docker image
Promotes a Docker image in a registry to another registry.
```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath("http://example.com/artifactory")

path.promote_docker_image("docker-staging", "docker-prod", "my-application", "0.5.1")
```

## Builds
```python
from artifactory import ArtifactoryBuildManager

arti_build = ArtifactoryBuildManager(
    "https://repo.jfrog.org/artifactory", project="proj_name", auth=("admin", "admin")
)

# Get all builds
all_builds = arti_build.builds
print(all_builds)

# Build Runs
build1 = all_builds[0]
all_runs = build1.runs
print(all_runs)

# Build Info
build_number1 = all_runs[0]
print(build_number1.info)

# Builds Diff
"""
  Compare a build artifacts/dependencies/environment with an older build to see what 
  has changed (new artifacts added, old dependencies deleted etc).  
"""
print(build_number1.diff(3))


# Build Promotion
"""
  Change the status of a build, optionally moving or copying the build's artifacts and its dependencies 
  to a target repository and setting properties on promoted artifacts.  
  All artifacts from all scopes are included by default while dependencies are not. Scopes are additive (or)
"""

build_number1.promote(
    ci_user="admin",
    properties={"components": ["c1", "c3", "c14"], "release-name": ["fb3-ga"]},
)
```

## Exception handling
Exceptions in this library are represented by `dohq_artifactory.exception.ArtifactoryException` or by `OSError`
If exception was caused by HTTPError you can always drill down the root cause by using following example:
```python
from artifactory import ArtifactoryPath
from dohq_artifactory.exception import ArtifactoryException

path = ArtifactoryPath(
    "http://my_arti:8080/artifactory/installer/", auth=("wrong_user", "wrong_pass")
)

try:
    path.stat()
except ArtifactoryException as exc:
    print(exc)  # clean artifactory error message
    # >>> Bad credentials
    print(
        exc.__cause__
    )  # HTTP error that triggered exception, you can use this object for more info
    # >>> 401 Client Error: Unauthorized for url: http://my_arti:8080/artifactory/installer/
```

# Admin area
You can manipulate with user\group\repository and permission. First, create `ArtifactoryPath` object without a repository
```python
from artifactory import ArtifactoryPath

artifactory_ = ArtifactoryPath(
    "https://artifactory.example.com/artifactory", auth=("user", "password")
)
```

You can see detailed use of `AdminObject` in file `.\tests\integration\test_admin.py`
## User
```python
# Find or create first way
from dohq_artifactory import generate_password, User

user = artifactory_.find_user("username")
if user is None:
    # User does not exist
    user = User(
        artifactory_, "username", "username@example.com", password=generate_password()
    )
    user.create()

# Find or create - second way
user = User(artifactory_, "username")
if not user.read():  # Return True if user exist
    # User does not exist
    user = User(
        artifactory_, "username", "username@example.com", password=generate_password()
    )
    user.create()


# Add to group
user.add_to_group("byname")

group = artifactory_.find_group("groupname")
user.add_to_group(group)
user.update()  # Don't forget update :)

enc_pwd = user.encrypted_password

# You can re-read from Artifactory
user.read()

user.delete()
```

### API Keys
```python
from dohq_artifactory import User

user = User(artifactory_, "username")

# create an API key
user.api_key.create()

# get API key
user.api_key.get()
# or using str() method
my_key = str(user.api_key)
# or using repr method
print(user.api_key)

# regenerate API key if one already exists
user.api_key.regenerate()

# remove API key for current user
user.api_key.revoke()

# remove all API keys in system, only if user has admin rights
user.api_key.revoke_for_all_users()
```

## Group
### Internal

```python
# Find
from dohq_artifactory import generate_password, Group

group = artifactory_.find_group("groupname")

# Create
if group is None:
    group = Group(artifactory_, "groupname")
    group.create()

# You can re-read from Artifactory
group.read()

# You can add multiple users at once to Group
group.users = ["admin", "anonymous"]
group.create()

# You can remove all users from a Group
group.users = []
group.create()

group.delete()
```

### GroupLDAP
https://www.jfrog.com/confluence/display/RTF/LDAP+Groups#LDAPGroups-UsingtheRESTAPI

```python
# Full DN path in artifactory
dn = "cn=R.DevOps.TestArtifactory,ou=Groups,dc=example,dc=com"
attr = "ldapGroupName=r.devops.testartifactory;groupsStrategy=STATIC;groupDn={}".format(
    dn
)
test_group = GroupLDAP(
    artifactory=artifactory_, name="r.devops.testartifactory", realm_attributes=attr
)
test_group.create()
```

## RepositoryLocal
```python
# Find
from dohq_artifactory import generate_password, RepositoryLocal

repo = artifactory_.find_repository_local("reponame")

# Create
if repo is None:
    # or RepositoryLocal.PYPI, RepositoryLocal.NUGET, etc
    repo = RepositoryLocal(artifactory_, "reponame", packageType=RepositoryLocal.DEBIAN)
    repo.create()

# You can re-read from Artifactory
repo.read()

repo.delete()
```

## RepositoryVirtual
```python
# Find
from dohq_artifactory import RepositoryVirtual

repo = artifactory_.find_repository_virtual("pypi.all")

# Create
if repo is None:
    # or RepositoryVirtual.PYPI, RepositoryLocal.NUGET, etc
    repo = RepositoryVirtual(
        artifactory_,
        "pypi.all",
        repositories=["pypi.snapshot", "pypi.release"],
        packageType=RepositoryVirtual.PYPI,
    )
    repo.create()

# You can re-read from Artifactory
repo.read()

local_repos = repo.repositories  # return List<RepositoryLocal>

repo.delete()
```

## RepositoryRemote
```python
# Find
from dohq_artifactory import RepositoryRemote

repo = artifactory_.find_repository_virtual("pypi.all")

# Create
if repo is None:
    # or RepositoryRemote.PYPI, RepositoryRemote.NUGET, etc
    repo = RepositoryRemote(
        artifactory_,
        "pypi.all",
        url="https://files.pythonhosted.org",
        packageType=RepositoryVirtual.PYPI,
    )
    repo.create()

# You can re-read from Artifactory
repo.read()

repo.delete()
```

## Project
```python
# Find
from artifactory import ArtifactoryPath
from dohq_artifactory import Project

artifactory_ = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/restricted-path", token="MY_TOKEN"
)
project = artifactory_.find_project("t1k1")

# Create
if project is None:
    project = Project(artifactory_, "t1k1", "t1k1_display_name")
    project.create()

# You can re-read from Artifactory
project.read()

project.delete()
```

## Get repository of any type
```python
# Find any repo by name
repo = artifactory_.find_repository("pypi.all")
```

## Iterate over repository artifacts
```python
# Get repo
repo = artifactory_.find_repository("pypi.all")

# Iterate over repo
for artifact in repo:
    print(artifact)
    print(artifact.properties)

# Result:
# http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.0.0-py3.whl
# {"pypi.name": ["my_package"], "pypy_version": ["1.0.0"]}
# http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.0.1.dev5-py3.whl
# {"pypi.name": ["my_package"], "pypy_version": ["1.0.1.dev5"]}
# http://my.artifactory.com/artifactory/pypi.all/other_package/other_package-0.0.1-py3.whl
# {"pypi.name": ["other_package"], "pypy_version": ["0.0.1"]}
# ...
```

## Access repository child item
Repo can bee accessed just like any other `ArtifactPath`:
```python
# Get repo
repo = artifactory_.find_repository("pypi.all")

# Access a folder within the repo
package = repo / "my_package"

# Result:
# ArtifactPath('http://my.artifactory.com/artifactory/pypi.all/my_package')

# Access a file within the repo
package = repo / "my_package" / "my_artifact.tar.gz"

# Result:
# ArtifactPath('http://my.artifactory.com/artifactory/pypi.all/my_package/my_artifact.tar.gz')
```

## Search for certain package artifacts
```python
# Get repo
repo = artifactory_.find_repository("pypi.all")

# Will generate and perform AQL query for getting artifacts by path or name
for artifacts in repo["my_package"]:
    print(artifact)
    print(artifact.properties)

# Result:
# http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.0.0-py3.whl
# {"pypi.name": ["my_package"], "pypy_version": ["1.0.0"], ...}
# http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.0.1.dev5-py3.whl
# {"pypi.name": ["my_package"], "pypy_version": ["1.0.1.dev5"], ...}
# http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.1.0-py3.whl
# {"pypi.name": ["my_package"], "pypy_version": ["1.1.0"], ...}
# ...

# Using partial match
for artifacts in repo["my_pack*"]:
    print(artifact)
    print(artifact.properties)

# Result:
# http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.0.0-py3.whl
# {"pypi.name": ["my_package"], "pypy_version": ["1.0.0"], ...}
# http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.0.1.dev5-py3.whl
# {"pypi.name": ["my_package"], "pypy_version": ["1.0.1.dev5"], ...}
# http://my.artifactory.com/artifactory/pypi.all/my_package_new_/my_package_new-0.0.1-py3.whl
# {"pypi.name": ["my_package_new"], "pypy_version": ["0.0.1"], ...}
# ...
```

Some types of repositories support specific ways of searching artifacts.
  * PyPi

    ```python
    # Get repo
    repo = artifactory_.find_repository("pypi.all")

    # Get artifacts by package name
    for artifacts in repo["my_package"]:
        print(artifact)
        print(artifact.properties)

    # Result:
    # http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.0.0-py3.whl
    # {"pypi.name": ["my_package"], "pypy_version": ["1.0.0"], ...}
    # http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.0.1.dev5-py3.whl
    # {"pypi.name": ["my_package"], "pypy_version": ["1.0.1.dev5"], ...}
    # http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.1.0-py3.whl
    # {"pypi.name": ["my_package"], "pypy_version": ["1.1.0"], ...}
    # ...

    # Get artifacts by specific version
    for artifacts in repo["my_package==1.0.0"]:
        print(artifact)
        print(artifact.properties)

    # Result:
    # http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.0.0-py3.whl
    # {"pypi.name": ["my_package"], "pypy_version": ["1.0.0"], ...}

    # Using other pip operators (result should be additionaly checked!)
    for artifacts in repo["my_package!=1.0.0"]:
        print(artifact)
        print(artifact.properties)

    # Result:
    # http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.0.1.dev5-py3.whl
    # {"pypi.name": ["my_package"], "pypy_version": ["1.0.1.dev5"], ...}
    # http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.1.0-py3.whl
    # {"pypi.name": ["my_package"], "pypy_version": ["1.1.0"], ...}
    # ...


    # In case of using > or < operators, the result should be additionaly checked
    # because Artifactory compares strings, not versions
    for artifacts in repo["my_package>=1.0.0"]:
        print(artifact)
        print(artifact.properties)

    # Result:
    # http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.0.1.dev5-py3.whl
    # {"pypi.name": ["my_package"], "pypy_version": ["1.0.1.dev5"], ...}
    # http://my.artifactory.com/artifactory/pypi.all/my_package/my_package-1.1.0-py3.whl
    # {"pypi.name": ["my_package"], "pypy_version": ["1.1.0"], ...}
    # ...
    ```

  * Docker

    ```python
    # Get repo
    repo = artifactory_.find_repository("docker.all")

    # Get artifacts by image name
    for artifacts in repo["my_image"]:
        print(artifact)
        print(artifact.properties)

    # Result:
    # http://my.artifactory.com/artifactory/docker.all/my_image/latest/manifest.json
    # {"docker.repoName": ["my_image"], "docker.manifest": ["latest"], ...}
    # http://my.artifactory.com/artifactory/docker.all/my_image/1.0.0/manifest.json
    # {"docker.repoName": ["my_image"], "docker.manifest": ["1.0.0"], ...}
    # http://my.artifactory.com/artifactory/docker.all/my_image/1.1.0/manifest.json
    # {"docker.repoName": ["my_image"], "docker.manifest": ["1.1.0"], ...}
    # ...

    # Get artifacts by specific version
    for artifacts in repo["my_image:1.0.0"]:
        print(artifact)
        print(artifact.properties)

    # Result:
    # http://my.artifactory.com/artifactory/docker.all/my_image/1.0.0/manifest.json
    # {"docker.repoName": ["my_image"], "docker.manifest": ["1.0.0"], ...}
    # ...

    for artifacts in repo["my_image:latest"]:
        print(artifact)
        print(artifact.properties)

    # Result:
    # http://my.artifactory.com/artifactory/docker.all/my_image/latest/manifest.json
    # {"docker.repoName": ["my_image"], "docker.manifest": ["latest"], ...}
    # ...

    # Partial search
    for artifacts in repo["my_package:*dev*"]:
        print(artifact)
        print(artifact.properties)
    # http://my.artifactory.com/artifactory/docker.all/my_image/dev/manifest.json
    # {"pypi.name": ["my_package"], "pypy_version": ["dev"]}
    # http://my.artifactory.com/artifactory/docker.all/my_image/1.0.1-dev5/manifest.json
    # {"pypi.name": ["my_package"], "pypy_version": ["1.0.1-dev5"]}
    # ...
    ```

  * Maven

    ```python
    # Get repo
    repo = artifactory_.find_repository("maven.all")

    # Get artifacts by group name
    for artifacts in repo["my.group"]:
        print(artifact)
        print(artifact.properties)

    # Result:
    # http://my.artifactory.com/artifactory/maven.all/my/group/package/1.0.0/maven-metadata.xml
    # ...
    # http://my.artifactory.com/artifactory/maven.all/my/group/another_package/1.2.3/maven-metadata.xml
    # ...

    # Get artifacts by group and package name
    for artifacts in repo["my.group:package"]:
        print(artifact)
        print(artifact.properties)

    # Result:
    # http://my.artifactory.com/artifactory/maven.all/my/group/package/1.0.0/maven-metadata.xml
    # http://my.artifactory.com/artifactory/maven.all/my/group/package/1.0.0/package-1.0.0-source.jar
    # http://my.artifactory.com/artifactory/maven.all/my/group/package/1.0.0/package-1.0.0-javadoc.jar
    # http://my.artifactory.com/artifactory/maven.all/my/group/package/1.0.0/package-1.0.0.pom
    # http://my.artifactory.com/artifactory/maven.all/my/group/package/1.0.0/package-1.0.0.jar
    # {"build.number": ["123"], "build.name": ["1.0.0"], ...}

    # http://my.artifactory.com/artifactory/maven.all/my/group/package/1.0.1/maven-metadata.xml
    # ...

    # Get artifacts by group, package name and version
    for artifacts in repo["my.group:package:1.0.0"]:
        print(artifact)
        print(artifact.properties)

    # Result:
    # http://my.artifactory.com/artifactory/maven.all/my/group/package/1.0.0/maven-metadata.xml
    # http://my.artifactory.com/artifactory/maven.all/my/group/package/1.0.0/package-1.0.0-source.jar
    # http://my.artifactory.com/artifactory/maven.all/my/group/package/1.0.0/package-1.0.0-javadoc.jar
    # http://my.artifactory.com/artifactory/maven.all/my/group/package/1.0.0/package-1.0.0.pom
    # http://my.artifactory.com/artifactory/maven.all/my/group/package/1.0.0/package-1.0.0.jar
    # {"build.number": ["123"], "build.name": ["1.0.0"], ...}
    ```

## PermissionTarget
Docs: https://www.jfrog.com/confluence/display/RTF/Managing+Permissions

Supports these roles:
- `PermissionTarget.ROLE_ADMIN` = `ADMIN + DELETE + DEPLOY + ANNOTATE + READ`
- `PermissionTarget.ROLE_DELETE` = `DELETE + DEPLOY + ANNOTATE + READ`
- `PermissionTarget.ROLE_DEPLOY` = `DEPLOY + ANNOTATE + READ`
- `PermissionTarget.ROLE_ANNOTATE` = `ANNOTATE + READ`
- `PermissionTarget.ROLE_READ` = `READ`

And for more modular control:
- `PermissionTarget.ADMIN` - Allows changing the permission settings for other users on this permission target
- `PermissionTarget.DELETE` - Allows deletion or overwriting of artifacts
- `PermissionTarget.DEPLOY` - Allows deploying artifacts and deploying to caches (i.e. populating caches with remote artifacts)
- `PermissionTarget.ANNOTATE` - Allows annotating artifacts and folders with metadata and properties
- `PermissionTarget.READ` - Allows reading and downloading of artifacts

```python
from dohq_artifactory import PermissionTarget

permission = artifactory_.find_permission_target("rule")

# See repositories, users or groups
permission.repositories
# Result:
# <RepositiryLocal repo1>
# <RepositiryLocal repo2>

permission.users
# Result:
# <User user1>
# <User user2>

permission.groups
# Result:
# <Group group1>
# <Group group2>

# Add repo (string or Repository) object
permission.add_repository("repo3", "repo4")
permission.add_repository(repo5_object)
# Or remove
permission.remove_repository("repo1", "repo2")

# Add user (string or User object) with specific permission
permission.add_user("user3", PermissionTarget.ROLE_ADMIN)
permission.add_user(
    user4_object, PermissionTarget.ROLE_READ + PermissionTarget.ROLE_WRITE
)  # You can add sum of permissions

# Or remove
permission.remove_user("user1", "user2")

# Add group (string or Group object) with permission
permission.add_group("group3", PermissionTarget.ROLE_ADMIN)
permission.add_group(
    group4_object, PermissionTarget.ROLE_READ + PermissionTarget.ROLE_WRITE
)  # You can add sum of permissions

# Or remove
permission.remove_group("group1", "group2")

permission.update()  # Update!!

permission.repositories
# Result:
# <RepositiryLocal repo3>
# <RepositiryLocal repo4>
# <RepositiryLocal repo5>

permission.users
# Result:
# <User user3>
# <User user4>

permission.groups
# Result:
# <Group group3>
# <Group group4>
```

## Token
https://www.jfrog.com/confluence/display/RTF5X/Access+Tokens#AccessTokens-RESTAPI
```python
from requests.auth import HTTPBasicAuth
from artifactory import ArtifactoryPath
from dohq_artifactory import Token

session = ArtifactoryPath(
    "https://artifactory_dns/artifactory",
    auth=("admin", "admin_password"),
    auth_type=HTTPBasicAuth,
    verify=False,
)

# Read token for readers group
group_name = "readers"
scope = "api:* member-of-groups:" + group_name
token = Token(session, scope=scope)
token.read()

# Create token for member of the readers
group_name = "readers"
scope = "api:* member-of-groups:" + group_name
subject = group_name
token = Token(
    session, scope=scope, username=subject, expires_in=31557600, refreshable=True
)
response = token.create()

print("Readonly token:")
print("Username: " + token.username)
print("Token: " + token.token["access_token"])
```

## Common
All `AdminObject`  support:
```python
user = artifactory_.find_user("username")
print(user.raw)  # JSON response from Artifactory

new_repo = RepositoryLocal(artifactory, "reponame")
# If some key you can't find in object, you can use this:
new_repo.additional_params["property_sets"] = ["my", "properties_sets"]
new_repo.create()

# All object support CRUD operations:
obj.read()  # Return True if user exist (and read from Artifactory), else return False
obj.create()
obj.update()
obj.delete()

# ArtifactoryPath have different find_ method:
artifactory_.find_user("name")
artifactory_.find_group("name")
artifactory_.find_repository_local("name")
artifactory_.find_permission_target("name")
artifactory_.find_project("project_key")
```

# Advanced

## Session ##

To re-use the established connection, you can pass ```session``` parameter to ArtifactoryPath:

```python
from artifactory import ArtifactoryPath
import requests

ses = requests.Session()
ses.auth = ("username", "password")
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/my-path-1", sesssion=ses
)
path.touch()

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/my-path-2", sesssion=ses
)
path.touch()
```


## SSL Cert Verification Options ##
See [Requests - SSL verification](http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification) for more details.

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0"
)
```
... is the same as
```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0", verify=True
)
```
Specify a local cert to use as client side certificate

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0",
    cert="/path_to_file/server.pem",
)
```
Disable host cert verification

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0", verify=False
)
```

**Note:** If host cert verification is disabled, `urllib3` will throw a [InsecureRequestWarning](https://urllib3.readthedocs.org/en/latest/security.html#insecurerequestwarning).
To disable these warning, one needs to call `urllib3.disable_warnings()`.
```python
import requests.packages.urllib3 as urllib3

urllib3.disable_warnings()
```

## Timeout on requests ##

The library supports `timeout` argument in the same meaner as [requests does](https://requests.readthedocs.io/en/master/user/advanced/#timeouts)
```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0"
)
```
... is the same as
```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0", timeout=None
)
```
Set 5 seconds timeout to your requests after which it will be terminated:
```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0", timeout=5
)
```

## Logging ##
The library can be configured to emit logging that will give you better insight into what it's doing.
Just configure [logging](https://docs.python.org/3/library/logging.html) module in your python script. 
Simplest example to add debug messages to a console:
```python
import logging
from artifactory import ArtifactoryPath

logging.basicConfig()
# set level only for artifactory module, if omitted, then global log level is used, eg from basicConfig
logging.getLogger("artifactory").setLevel(logging.DEBUG)

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/restricted-path", apikey="MY_API_KEY"
)
```


## Global Configuration File ##

Artifactory Python module also can specify all connection-related settings in a central file, given by environment
variable ```$DOHQ_ARTIFACTORY_PYTHON_CFG``` (default if not set: ```~/.artifactory_python.cfg```) that is read upon
the creation of first ```ArtifactoryPath``` object and is stored globally. For instance, you can specify per-instance
settings of authentication tokens, so that you won't need to explicitly pass ```auth``` parameter to ```ArtifactoryPath```.

Example:

```ini
[DEFAULT]
username = nameforallinstances

[http://artifactory-instance.com/artifactory]
password = ilikerandompasswords
verify = false

[another-artifactory-instance.com/artifactory]
password = @dmin
cert = ~/mycert
```

Whether or not you specify ```http://``` or ```https://```, the prefix is not essential. The module will first try to 
locate the best match and then try to match URLs without prefixes. So in the config, if you specify 
```https://my-instance.local``` and call ```ArtifactoryPath``` with ```http://my-instance.local```, it will still do 
the right thing.


# Contribute
[About contributing and testing](docs/CONTRIBUTE.md)

# Advertising
- [artifactory-du](https://github.com/devopshq/artifactory-du) - estimate file space usage. Summarize disk usage in 
  JFrog Artifactory of the set of FILEs, recursively for directories.
- [artifactory-cleanup](https://github.com/devopshq/artifactory-cleanup) - is an extended and flexible cleanup tool for JFrog Artifactory.
