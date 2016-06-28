#!/bin/sh -ex

# Clean and then create the artifacts directory:
rm -rf exported-artifacts
mkdir -p exported-artifacts

# Create a settings file that uses the our artifactory server as proxy
# for all repositories:
settings="$(pwd)/settings.xml"
cat > "${settings}" <<.
<settings>
  <mirrors>

    <mirror>
      <id>ovirt-artifactory</id>
      <url>http://artifactory.ovirt.org/artifactory/ovirt-mirror</url>
      <mirrorOf>*</mirrorOf>
    </mirror>

    <mirror>
      <id>maven-central</id>
      <url>http://repo.maven.apache.org/maven2</url>
      <mirrorOf>*</mirrorOf>
    </mirror>

  </mirrors>
</settings>
.

version="$(python ansible/lib/version.py)"

# Build the code generator and run it:
mvn package -s "${settings}"

# Generate the .tar.gz file containing generated ansible modules
tar_name="ovirt-engine-ansible4"
tar_prefix="${tar_name}-${version}"
tar_file="${PWD}/${tar_prefix}.tar.gz"
tar -czf "${tar_file}" -C ansible .

# Build the RPM:
cp "${tar_file}" packaging/.
pushd packaging
  export tar_version="${version}"
  export tar_url="$(basename ${tar_file})"
  export rpm_dist="$(rpm --eval '%dist')"
  export rpm_release="0.0.a0${rpm_dist}"
  ./build.sh
popd

# Copy the RPM files to the exported artifacts directory:
for file in "${tar_file}" $(find packaging -type f -name '*.rpm'); do
  echo "Archiving file \"$file\"."
  mv "$file" exported-artifacts
done
