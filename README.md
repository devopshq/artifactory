# Python interface library for Jfrog Artifactory #

[![docs](https://img.shields.io/readthedocs/pip.svg)](https://devopshq.github.io/artifactory/)[![dohq-artifactory build Status](https://travis-ci.org/devopshq/artifactory.svg?branch=master)](https://travis-ci.org/devopshq/artifactory) [![dohq-artifactory code quality](https://api.codacy.com/project/badge/Grade/ce32469db9d948bcb56d50532e0c0005)](https://www.codacy.com/app/tim55667757/artifactory/dashboard) [![dohq-artifactory on PyPI](https://img.shields.io/pypi/v/dohq-artifactory.svg)](https://pypi.python.org/pypi/dohq-artifactory) [![dohq-artifactory license](https://img.shields.io/pypi/l/dohq-artifactory.svg)](https://github.com/devopshq/artifactory/blob/master/LICENSE)

This module is intended to serve as a logical descendant of [pathlib](https://docs.python.org/3/library/pathlib.html), a Python 3 module for object-oriented path manipulations. As such, it implements everything as closely as possible to the origin with few exceptions, such as stat().

# Tables of Contents 
- [Install](#install)
- [Usage](#usage)
    - [Walking Directory Tree](#walking-directory-tree)
    - [Downloading Artifacts](#downloading-artifacts)
    - [Uploading Artifacts](#uploading-artifacts)
    - [Copy Artifacts](#copy-artifacts)
    - [Remove Artifacts](#remove-artifacts)
    - [Artifact properties](#artifact-properties)
    - [Artifactory Query Language](#artifactory-query-language)
    - [FileStat](#filestat)
- [Admin area](#admin-area)
    - [User](#user)
    - [Group](#group)
        - [ Internal](#internal)
        - [ GroupLDAP](#groupldap)
    - [RepositoryLocal](#repositorylocal)
    - [PermissionTarget](#permissiontarget)
    - [Common](#common)
- [Advanced](#advanced)
    - [Authentication](#authentication)
    - [Session](#session)
    - [SSL Cert Verification Options](#ssl-cert-verification-options)
    - [Global Configuration File](#global-config-file)
- [Contribute](#contribute)

# Install #
```bash
python3 -mpip install dohq-artifactory
```
# Usage 

## Walking Directory Tree ##

Getting directory listing:

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/gradle-ivy-local")
for p in path:
    print(p)
```

Find all .gz files in current dir, recursively:

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/")

for p in path.glob("**/*.gz"):
    print(p)
```

## Downloading Artifacts ##

Download artifact to a local filesystem:

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz")
    
with path.open() as fd:
    with open("tomcat.tar.gz", "wb") as out:
        out.write(fd.read())
```

## Uploading Artifacts ##

Deploy a regular file ```myapp-1.0.tar.gz```

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0")
path.mkdir()

path.deploy_file('./myapp-1.0.tar.gz')
```
Deploy a debian package ```myapp-1.0.deb```

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/ubuntu-local/pool")
path.deploy_deb('./myapp-1.0.deb', 
                distribution='trusty',
                component='main',
                architecture='amd64')
```

## Copy Artifacts ##
Copy artifact from this path to destinaiton.
If files are on the same instance of artifactory, lightweight (local)
copying will be attempted.

The suppress_layouts parameter, when set to True, will allow artifacts
from one path to be copied directly into another path without enforcing
repository layouts. The default behaviour is to copy to the repository
root, but remap the [org], [module], [baseVer], etc. structure to the
target repository.

For example, if we have a builds repository using the default maven2
repository where we publish our builds. We also have a published
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

for p in ArtifactoryPath("http://example.com/artifactory/published/product/product/1.0.0.tar"):
    print p
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
```

## Remove Artifacts ##
```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz")

if path.exists():
    path.unlink()
```

## Artifact properties ##
You can get and set (or remove) properties from artifact:
```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz")

# Get properties
properties = path.properties
print(properties)

# Update one properties or add if does not exist
properties['qa'] = 'tested'
path.properties = properties

# Remove properties
properties.pop('release')
path.properties = properties
```

## Artifactory Query Language
You can use [Artifactory Query Language](https://www.jfrog.com/confluence/display/RTF/Artifactory+Query+Language) in python.

```python
from artifactory import ArtifactoryPath
aql = ArtifactoryPath( "http://my-artifactory/artifactory") # path to artifactory, NO repo

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
args = ["items.find", {"$and": [
    {
        "repo": {"$eq": "repo"}
    },
    {
        "$or": [
            {"path": {"$match": "*path1"}},
            {"path": {"$match": "*path2"}},
        ]
    },
]
}]

# artifacts_list contains raw data (list of dict)
# Send query:
# items.find({"$and": [{"repo": {"$eq": "repo"}}, {"$or": [{"path": {"$match": "*path1"}}, {"path": {"$match": "*path2"}}]}]})
artifacts_list = aql.aql(*args)

# You can convert to pathlib object:
artifact_pathlib = map(aql.from_aql, artifacts_list)
artifact_pathlib_list = list(map(aql.from_aql, artifacts_list))
```


## FileStat
You can get hash (`md5`, `sha1`), create and change date:

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz")

# Get FileStat
stat = ArtifactoryPath.stat(path)
print(stat)
print(stat.md5)
print(stat.sha1)
print(stat.ctime)
print(stat.is_dir)
print(stat.size)
```

# Admin area
You can manipulate with user\group\repository and permission. First, create `ArtifactoryPath` object without repository
```python
from artifactory import ArtifactoryPath
artifactory_ = ArtifactoryPath('https://artifactory.example.com/artifactory', auth=('user', 'password'))
```

You can see detailed use `AdminObject` in file `.\tests\integration\test_admin.py`
## User
```python
# Find or create first way
from dohq_artifactory import generate_password, User
user = artifactory_.find_user('username')
if user is None:
    # User does not exist
    user = User(artifactory_, 'username', 'username@example.com', password=generate_password())
    user.create()

# Find or create - second way
user = User(artifactory_, 'username')
if not user.read(): # Return True if user exist
    # User does not exist
    user = User(artifactory_, 'username', 'username@example.com', password=generate_password())
    user.create()


# Add to group
user.add_to_group('byname')

group = artifactory_.find_group('groupname')
user.add_to_group(group)
user.update() # Don't forget update :)

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
group = artifactory_.find_group('groupname')

# Create
if group is None:
    group = Group(artifactory_, 'groupname')
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
attr = "ldapGroupName=r.devops.testartifactory;groupsStrategy=STATIC;groupDn={}".format(dn)
test_group = GroupLDAP(artifactory=artifactory_, name='r.devops.testartifactory', realmAttributes=attr)
test_group.create()
```

## RepositoryLocal
```python
# Find
from dohq_artifactory import generate_password, RepositoryLocal
repo = artifactory_.find_repository_local('reponame')

# Create
if repo is None:
    # or RepositoryLocal.PYPI, RepositoryLocal.NUGET, etc
    repo = RepositoryLocal(artifactory_, 'reponame',packageType=RepositoryLocal.DEBIAN)
    repo.create()

# You can re-read from Artifactory
repo.read()

repo.delete()
```

## PermissionTarget
Docs: https://www.jfrog.com/confluence/display/RTF/Managing+Permissions

Supported this role:
- PermissionTarget.ROLE_ADMIN = `ADMIN + DELETE + DEPLOY + ANNOTATE + READ`
- PermissionTarget.ROLE_DELETE = `DELETE + DEPLOY + ANNOTATE + READ`
- PermissionTarget.ROLE_DEPLOY = `DEPLOY + ANNOTATE + READ`
- PermissionTarget.ROLE_ANNOTATE = `ANNOTATE + READ`
- PermissionTarget.ROLE_READ = `READ`

And right:
- `PermissionTarget.ADMIN` - Allows changing the permission settings for other users on this permission target
- `PermissionTarget.DELETE` - Allows deletion or overwriting of artifacts
- `PermissionTarget.DEPLOY` - Allows deploying artifacts and deploying to caches (i.e. populating caches with remote artifacts)
- `PermissionTarget.ANNOTATE` - Allows annotating artifacts and folders with metadata and properties
- `PermissionTarget.READ` - Allows reading and downloading of artifacts

```python
from dohq_artifactory import PermissionTarget
permission = artifactory_.find_permission_target('rule')

# Add repo as string or RepositoryLocal object
permission.add_repository('repo1', 'repo2')

# Add group or user with permission
permission.add_user(user_object, PermissionTarget.ROLE_ADMIN)
permission.add_group('groupname, PermissionTarget.ROLE_READ)

permission.update() # Update!!

```

## Common
All `AdminObject`  support:
```python
artifactory_.find_user('username')
print(user.raw) # JSON response from Artifactory

new_repo = RepositoryLocal(artifactory, 'reponame')
# If some key you can't find in object, you can use this:
new_repo.additional_params['property_sets'] = ['my', 'properties_sets']
new_repo.create()

# All object support CRUD operations:
obj.read() # Return True if user exist (and read from Artifactory), else return False
obj.create()
obj.update()
obj.delete()

# ArtifactoryPath have different find_ method:
artifactory_.find_user('name')
artifactory_.find_group('name')
artifactory_.find_repository_local('name')
artifactory_.find_permission_target('name')
```

# Advanced

## Authentication ##

To provide username and password to access restricted resources, you can pass ```auth``` parameter to ArtifactoryPath:

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/restricted-path",
    auth=('admin', 'ilikerandompasswords'))
path.touch()
```

## Session ##

To re-use the established connection, you can pass ```session``` parameter to ArtifactoryPath:

```python
from artifactory import ArtifactoryPath
import requests
ses = requests.Session()
ses.auth = ('username', 'password')
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/my-path-1",
    sesssion=ses)
path.touch()

path = ArtifactoryPath(
    "http://my-artifactory/artifactory/myrepo/my-path-2",
    sesssion=ses)
path.touch()
```


## SSL Cert Verification Options ##
See [Requests - SSL verification](http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification) for more details.  

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0")
```
... is the same as
```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0", 
    verify=True)
```
Specify a local cert to use as client side certificate

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0",
    cert="/path_to_file/server.pem")
```
Disable host cert verification 

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0",
    verify=False)
```

**Note:** If host cert verification is disabled urllib3 will throw a [InsecureRequestWarning](https://urllib3.readthedocs.org/en/latest/security.html#insecurerequestwarning).  
To disable these warning, one needs to call urllib3.disable_warnings().
```python
import requests.packages.urllib3 as urllib3
urllib3.disable_warnings()
```

## Global Configuration File ##

Artifactory Python module also has a way to specify all connection-related settings in a central file, ```~/.artifactory_python.cfg``` that is read upon the creation of first ```ArtifactoryPath``` object and is stored globally. For instance, you can specify per-instance settings of authentication tokens, so that you won't need to explicitly pass ```auth``` parameter to ```ArtifactoryPath```.

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

Whether or not you specify ```http://``` or ```https://``` prefix is not essential. The module will first try to locate the best match and then try to match URLs without prefixes. So if in the config you specify ```https://my-instance.local``` and call ```ArtifactoryPath``` with ```http://my-instance.local```, it will still do the right thing. 


# Contribute
[About contribute](docs/CONTRIBUTE.md)
