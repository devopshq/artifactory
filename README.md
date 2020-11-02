# Python interface library for Jfrog Artifactory #


[![docs](https://img.shields.io/readthedocs/pip.svg)](https://devopshq.github.io/artifactory/)[![dohq-artifactory build Status](https://travis-ci.org/devopshq/artifactory.svg?branch=master)](https://travis-ci.org/devopshq/artifactory) [![dohq-artifactory code quality](https://api.codacy.com/project/badge/Grade/ce32469db9d948bcb56d50532e0c0005)](https://www.codacy.com/app/tim55667757/artifactory/dashboard) [![dohq-artifactory on PyPI](https://img.shields.io/pypi/v/dohq-artifactory.svg)](https://pypi.python.org/pypi/dohq-artifactory) [![dohq-artifactory license](https://img.shields.io/pypi/l/dohq-artifactory.svg)](https://github.com/devopshq/artifactory/blob/master/LICENSE)

This module is intended to serve as a logical descendant of [pathlib](https://docs.python.org/3/library/pathlib.html), a Python 3 module for object-oriented path manipulations. As such, it implements everything as closely as possible to the origin with few exceptions, such as stat().

![](https://img.shields.io/badge/status-supported-green.svg)`dohq-artifactory` is a live python package for Jfrog Artifactory. It was forked from outdated [parallels/artifactory](https://github.com/parallels/artifactory) and supports all functionality from the original package.

# Tables of Contents

<!-- toc -->

- [Install](#install)
- [Usage](#usage)
  * [Authentication](#authentication)
  * [Artifactory SaaS](#artifactory-saas)
  * [Walking Directory Tree](#walking-directory-tree)
  * [Downloading Artifacts](#downloading-artifacts)
  * [Downloading Artifacts folder as archive](#downloading-artifacts-folder-as-archive)
  * [Uploading Artifacts](#uploading-artifacts)
  * [Copy Artifacts](#copy-artifacts)
  * [Move Artifacts](#move-artifacts)
  * [Remove Artifacts](#remove-artifacts)
  * [Artifact properties](#artifact-properties)
  * [Artifactory Query Language](#artifactory-query-language)
  * [FileStat](#filestat)
- [Admin area](#admin-area)
  * [User](#user)
  * [Group](#group)
    + [Internal](#internal)
    + [GroupLDAP](#groupldap)
  * [RepositoryLocal](#repositorylocal)
  * [RepositoryVirtual](#repositoryvirtual)
  * [RepositoryRemote](#repositoryremote)
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
  * [Troubleshooting](#troubleshooting)
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

```python
from artifactory import ArtifactoryPath

# API_KEY
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/restricted-path", apikey="MY_API_KEY"
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
If you use Artifactory SaaS solution - use `ArtifactorySaaSPath` class
```python
from artifactory import ArtifactorySaaSPath

# API_KEY
path = ArtifactorySaaSPath(
    "https://myartifactorysaas.jfrog.io/myartifactorysaas/folder/path.xml",
    apikey="MY_API_KEY",
)
```
We have to use other class, because as a SaaS service, the URL is different from an on-prem installation and the REST API endpoints.


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

## Downloading Artifacts folder as archive ##
Download artifact folder to a local filesystem as archive (supports zip/tar/tar.gz/tgz)
Allows to specify archive type and request checksum for the folder
Note: Archiving should be enabled on the server!
```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my_url:8080/artifactory/my_repo/winx64/aas", auth=("user", "password")
)

with path.download_folder_archive(archive_type="zip", check_sum=False) as archive:
    with open(r"D:\target.zip", "wb") as out:
        out.write(archive.read())
```

## Uploading Artifacts ##

Deploy a regular file ```myapp-1.0.tar.gz```

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0"
)
path.mkdir()

path.deploy_file("./myapp-1.0.tar.gz")
```
Deploy a debian package ```myapp-1.0.deb```

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath("http://my-artifactory/artifactory/ubuntu-local/pool")
path.deploy_deb(
    "./myapp-1.0.deb", distribution="trusty", component="main", architecture="amd64"
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
    print (p)
# http://example.com/artifactory/published/production/foo-0.0.1.gz
# http://example.com/artifactory/published/production/foo-0.0.1.pom

for p in ArtifactoryPath(
    "http://example.com/artifactory/published/product/product/1.0.0.tar"
):
    print p
# http://example.com/artifactory/published/product/product/1.0.0/product-1.0.0.tar.gz
# http://example.com/artifactory/published/product/product/1.0.0/product-1.0.0.tar.pom

"""
Using copy with suppress_layouts=True, the contents inside our source are copied
directly inside our dest as we intended.
"""

source.copy(dest, suppress_layouts=True)
for p in dest:
    print (p)
"""
http://example.com/artifactory/published/production/foo-0.0.1.gz
http://example.com/artifactory/published/production/foo-0.0.1.pom
http://example.com/artifactory/published/production/product-1.0.0.tar.gz
http://example.com/artifactory/published/production/product-1.0.0.tar.pom
"""
```

## Move Artifacts
Move artifact from this path to destination.

```python
from artifactory import ArtifactoryPath

source = ArtifactoryPath("http://example.com/artifactory/builds/product/product/1.0.0/")
dest = ArtifactoryPath("http://example.com/artifactory/published/production/")

source.move(dest)
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
You can get and set (or remove) properties from artifact:
```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz"
)

# Get properties
properties = path.properties
print(properties)

# Update one properties or add if does not exist
properties["qa"] = "tested"
path.properties = properties

# Remove properties
properties.pop("release")
path.properties = properties
```

## Artifactory Query Language
You can use [Artifactory Query Language](https://www.jfrog.com/confluence/display/RTF/Artifactory+Query+Language) in python.

```python
from artifactory import ArtifactoryPath

aql = ArtifactoryPath(
    "http://my-artifactory/artifactory"
)  # path to artifactory, NO repo

# dict support
# Send query:
# items.find({"repo": "myrepo"})
artifacts = aql.aql("items.find", {"repo": "myrepo"})

# list support.
# Send query:
# items.find().include("name", "repo")
artifacts = aql.aql("items.find()", ".include", ["name", "repo"])

#  support complex query
# items.find({"$and": [{"repo": {"$eq": "repo"}}, {"$or": [{"path": {"$match": "*path1"}}, {"path": {"$match": "*path2"}}]}]})
args = [
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
# Send query:
# items.find({"$and": [{"repo": {"$eq": "repo"}}, {"$or": [{"path": {"$match": "*path1"}}, {"path": {"$match": "*path2"}}]}]})
artifacts_list = aql.aql(*args)

# You can convert to pathlib object:
artifact_pathlib = map(aql.from_aql, artifacts_list)
artifact_pathlib_list = list(map(aql.from_aql, artifacts_list))
```


## FileStat
You can get hash (`md5`, `sha1`, `sha256`), create date, and change date:

```python
from artifactory import ArtifactoryPath

path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz"
)

# Get FileStat
stat = ArtifactoryPath.stat(path)
print(stat)
print(stat.md5)
print(stat.sha1)
print(stat.sha256)
print(stat.ctime)
print(stat.is_dir)
print(stat.size)
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

enc_pwd = user.encryptedPassword

# You can re-read from Artifactory
user.read()

user.delete()
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
    artifactory=artifactory_, name="r.devops.testartifactory", realmAttributes=attr
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

## Troubleshooting ##
Use [logging](https://docs.python.org/3/library/logging.html) for debug:
```python
def init_logging():
    logger_format_string = "%(thread)5s %(module)-20s %(levelname)-8s %(message)s"
    logging.basicConfig(
        level=logging.DEBUG, format=logger_format_string, stream=sys.stdout
    )


init_logging()
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/restricted-path",
    auth=("USERNAME", "PASSWORD or API_KEY"),
)

path.touch()
```


## Global Configuration File ##

Artifactory Python module also can specify all connection-related settings in a central file, ```~/.artifactory_python.cfg``` that is read upon the creation of first ```ArtifactoryPath``` object and is stored globally. For instance, you can specify per-instance settings of authentication tokens, so that you won't need to explicitly pass ```auth``` parameter to ```ArtifactoryPath```.

Example:

```ini
[http://artifactory-instance.com/artifactory]
username = deployer
password = ilikerandompasswords
verify = false

[another-artifactory-instance.com/artifactory]
username = foo
password = @dmin
cert = ~/mycert
```

Whether or not you specify ```http://``` or ```https://```, the prefix is not essential. The module will first try to locate the best match and then try to match URLs without prefixes. So in the config, if you specify ```https://my-instance.local``` and call ```ArtifactoryPath``` with ```http://my-instance.local```, it will still do the right thing.


# Contribute
[About contributing and testing](docs/CONTRIBUTE.md)

# Advertising
- [artifactory-du](https://github.com/devopshq/artifactory-du) - estimate file space usage. Summarize disk usage in JFrog Artifactory of the set of FILEs, recursively for directories.
- [artifactory-cleanup-rules](https://github.com/devopshq/artifactory-du/issues/2) - python-script for Artifactory intelligence cleanup rules with config.
