# Python interface library for Jfrog Artifactory #

[![dohq-artifactory build Status](https://travis-ci.org/devopshq/artifactory.svg?branch=master)](https://travis-ci.org/devopshq/artifactory) [![dohq-artifactory code quality](https://api.codacy.com/project/badge/Grade/ce32469db9d948bcb56d50532e0c0005)](https://www.codacy.com/app/tim55667757/artifactory/dashboard) [![dohq-artifactory on PyPI](https://img.shields.io/pypi/v/dohq-artifactory.svg)](https://pypi.python.org/pypi/dohq-artifactory) [![dohq-artifactory license](https://img.shields.io/pypi/l/dohq-artifactory.svg)](https://github.com/devopshq/artifactory/blob/master/LICENSE)

This module is intended to serve as a logical descendant of [pathlib](https://docs.python.org/3/library/pathlib.html), a Python 3 module for object-oriented path manipulations. As such, it implements everything as closely as possible to the origin with few exceptions, such as stat().

# Usage Examples #

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

# Artifactory AQL #

Supported [Artifactory-AQL](https://www.jfrog.com/confluence/display/RTF/Artifactory+Query+Language)

```python
from artifactory import ArtifactoryPath
aql = ArtifactoryPath( "http://my-artifactory/artifactory") # path to artifactory, NO repo

# dict support
artifacts = aql.aql("items.find", {"repo": "myrepo"}) # send query: items.find({"repo": "myrepo"})

# list support
artifacts = aql.aql("items.find()", ".include", ["name", "repo"]) # send query: items.find().include("name", "repo")

#  support complex query
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

# send query: 
# items.find({"$and": [{"repo": {"$eq": "repo"}}, {"$or": [{"path": {"$match": "*path1"}}, {"path": {"$match": "*path2"}}]}]})
# artifacts_list contains raw data (list of dict)
artifacts_list = aql.aql(*args) 

# You can convert to patlib object:
artifact_pathlib = map(aql.from_aql, artifacts_list)
artifact_pathlib_list = list(map(aql.from_aql, artifacts_list))
```
