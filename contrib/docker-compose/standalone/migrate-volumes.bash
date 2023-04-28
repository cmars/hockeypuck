#!/bin/bash

set -euo pipefail

cat <<EOF

This utility migrates volumes from another docker-compose project to this one.
It makes lots of assumptions about docker-compose's defaults; here be dragons!

WARNING: Don't continue if you have already spun up a docker-compose project
inside this directory; it will not end well.

EOF

targetProjectDir=$(dirname "$(readlink -f "$0")")
targetProjectName=${targetProjectDir##*/}

echo "Checking for target volumes..."
if [[ $(docker volume list | awk "/ ${targetProjectName}_/ {print \$2}" | tee >(cat 1>&2)) ]]; then
    echo "WARNING: the above target volume(s) already exist."
    echo -n 'Continue anyway? [y/N] '
    read -r response
    if [[ "$response" != y && "$response" != Y ]]; then
        echo "Aborting"
        exit 1
    fi
else
    echo "Done"
fi

echo "The following hockeypuck docker-compose projects have been detected:"
echo
docker volume list | awk -F_ '/_hkp_data/ {print $1}' | awk '{print $2}' | sort -u
echo
echo -n 'Enter a project to source data from: '
read -r sourceProjectName
echo

sourceVolumeList=( $(docker volume list | awk "/ ${sourceProjectName}_/ {print \$2}") )
totalVolumeSize=0
for sourceVolume in "${sourceVolumeList[@]}"; do
    sourceVolumeSize=$(du -xsk "$(docker inspect "$sourceVolume" | awk -F'"' '/Mountpoint/ {print $4}')" | awk '{print $1}')
    (( totalVolumeSize = totalVolumeSize + sourceVolumeSize ))
done

dockerRootFree=$(df -k "$(docker system info 2>/dev/null | awk '/Docker Root Dir/ {print $4}')" | awk '/^\// {print $4}')
if (( totalVolumeSize > dockerRootFree )); then
    echo "WARNING: not enough disk space to duplicate source volumes"
    echo "(${totalVolumeSize} kB required, ${dockerRootFree} kB available)"
    echo "If you wish to proceed, the data will be MOVED from the old volumes"
    echo "to the new ones instead of cloned."
    echo "BEWARE: this is EXPERIMENTAL and may result in data loss"
    echo
    echo "The following volumes will be DRAINED: ${sourceVolumeList[*]}"
    incremental=true
else
    echo "The following volumes will be CLONED: ${sourceVolumeList[*]}"
fi
echo
echo -n "Proceed? [y/N] "
read -r response
if [[ "$response" != y && "$response" != Y ]]; then
    echo "Aborting"
    exit 1
fi
echo

# let's go

for sourceVolume in "${sourceVolumeList[@]}"; do
    targetVolume=$targetProjectName${sourceVolume#"${sourceProjectName}"}
    if ! docker volume inspect "$targetVolume" >/dev/null 2>&1; then
        echo "Creating $targetVolume"
        docker volume create "$targetVolume"
    fi
    if [[ ${incremental:-} ]]; then
        echo "Moving $sourceVolume to $targetVolume"
        docker run --rm --name "$sourceVolume-to-$targetVolume" \
            -v "$sourceVolume:/source" -v "$targetVolume:/target" instrumentisto/rsync-ssh \
            /bin/sh -c 'rsync -a --remove-source-files /source/ /target/ && find /source -type d -empty -delete'
        echo "$sourceVolume is now empty"
    else
        echo "Cloning $sourceVolume to $targetVolume"
        docker run --rm --name "$sourceVolume-to-$targetVolume" \
            -v "$sourceVolume:/source" -v "$targetVolume:/target" instrumentisto/rsync-ssh \
            rsync -a /source/ /target/
    fi
done

echo "Done!"
if [[ ${incremental:-} ]]; then
    echo "The original volume(s) have been drained of data"
else
    echo "The original volume(s) are unchanged"
fi

cat <<EOF

If the only errors you saw above were "find: /source: Resource Busy" then this
script probably worked. Congratulations! You're not done yet though.

You will need to manually fix some things because your new project will expect
to be starting from an empty set of data volumes, and that's no longer true.

1. Copy POSTGRES_USER and POSTGRES_PASSWORD across from your old project to 
the '.env' file in this directory.

2. Incant 'docker-compose up'. It will fail, but that's OK. Hit Ctrl-C to quit.

3. Incant the following:

docker-compose -f docker-compose.yml -f docker-compose-tools.yml \
    run --rm --entrypoint /bin/sh import-keys \
    -x -c 'mkdir -p /import/dump && touch /import/dump/.import-timestamp'

4. Run 'docker-compose up' again. It should work this time.

EOF
