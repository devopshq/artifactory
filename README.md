# artifactory: a Python interface library for Jfrog Artifactory #

This module is intended to serve as a logical descendant of [pathlib](https://docs.python.org/3/library/pathlib.html), a Python 3 module for object-oriented path manipulations. As such, it implements everything as closely as possible to the origin with few exceptions, such as stat().

# Usage Examples #

Getting directory listing:

    from artifactory import ArtifactoryPath
    path = ArtifactoryPath("http://repo.jfrog.org/artifactory/gradle-ivy-local")
    for p in path.iterdir():
        print p

Find all .gz files in current dir, recursively:

    from artifactory import ArtifactoryPath
    path = ArtifactoryPath("http://repo.jfrog.org/artifactory/distributions/org/")

    for p in path.glob("**/*.gz"):
        print p

Download artifact to a local filesystem:

    from artifactory import ArtifactoryPath
    path = ArtifactoryPath("http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz")
    
    with path.open() as fd:
        with open("tomcat.tar.gz", "w") as out:
            out.write(fd.read())

