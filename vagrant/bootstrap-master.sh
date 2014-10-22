#!/usr/bin/env bash

apt-get update

apt-get install -y build-essential
apt-get install -y autoconf
apt-get install -y libtool
apt-get install -y uuid-dev

# Set up passwordless ssh
#if [ ! -f /home/vagrant/.ssh/petuum_insecure_key ]; then
#  su - vagrant -c "cp /petuum/vagrant/petuum_insecure_key /home/vagrant/.ssh/petuum_insecure_key"
#  su - vagrant -c "chmod 600 /home/vagrant/.ssh/petuum_insecure_key"
#  su - vagrant -c "cp /petuum/vagrant/petuum_insecure_key.pub /home/vagrant/.ssh/petuum_insecure_key.pub"
#  su - vagrant -c "chmod 644 /home/vagrant/.ssh/petuum_insecure_key.pub"
#  su - vagrant -c "echo 'IdentityFile /home/vagrant/.ssh/petuum_insecure_key' >> /home/vagrant/.ssh/config"
#fi

#read -d '' deploy_script <<"EOF"
##!/bin/bash
#petuum_hosts=$(getent ahosts | awk '{print $2}' | grep 'petuum-node[^0]')
#for host in ${petuum_hosts} ; do
#  echo Deploying to ${host}
#  rsync -avrPe 'ssh -o "StrictHostKeyChecking=no"' /petuum vagrant@${host}:/
#done
#EOF

#echo "${deploy_script}" > /bin/petuum-deploy
#chmod a+x /bin/petuum-deploy
