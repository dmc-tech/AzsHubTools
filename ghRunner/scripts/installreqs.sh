
#!/bin/bash
set -x #Debug

while getopts r:t:o: option
do
  case "${option}"
  in
    r) REPO=${OPTARG};;
    t) TOKEN=${OPTARG};;
    o) OWNER=${OPTARG};;
  esac
done


# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

#Install kubectl
sudo snap install kubectl --classic

# Install Helm
sudo snap install helm --classic


# Install yq
sudo snap install yq -y

# Install sipcalc
sudo apt-get update
sudo apt-get install sipcalc -y

#Install jq
sudo apt-get update
sudo apt install jq -y

# Install Docker
sudo apt-get update
sudo apt-get install  apt-transport-https  ca-certificates  curl gnupg  lsb-release -y

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io -y

sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker 

sudo chmod 666 /var/run/docker.sock


# NPM
sudo apt-get update
sudo apt-get install npm -y

# Yarn
sudo npm install --global yarn

# Install unzip
# https://github.com/Azure/setup-helm/issues/10
sudo apt-get update
sudo apt-get install unzip -y

# Update git
sudo apt-get update
sudo add-apt-repository ppa:git-core/ppa -y
sudo apt-get update
sudo apt-get install git -y
git --version


#Install GitHub Runner Agent
mkdir actions-runner && cd actions-runner 
# Download the latest runner package
curl -o actions-runner-linux-x64-2.277.1.tar.gz -L https://github.com/actions/runner/releases/download/v2.277.1/actions-runner-linux-x64-2.277.1.tar.gz
# Extract the installer
tar xzf ./actions-runner-linux-x64-2.277.1.tar.gz

payload=$(curl -sX POST -H "Authorization: token ${TOKEN}"  https://api.github.com/repos/${OWNER}/${REPO}/actions/runners/registration-token)
export RUNNER_TOKEN=$(echo $payload | jq .token --raw-output)

 ./config.sh --url https://github.com/${OWNER}/${REPO} --token ${RUNNER_TOKEN}

sudo ./svc.sh install
sudo ./svc.sh start

#Debug - check what folder stuff is being put in...
find . | sed -e "s/[^-][^\/]*\// |/g" -e "s/|\([^ ]\)/|-\1/"



# https://docs.microsoft.com/en-us/azure-stack/user/ci-cd-github-action-login-cli?view=azs-2102
# Create SP for access to AzureStackHub User Sub.  Needs to be done prior to creating VM, so this is FYI only

#az cloud register \
#    -n "AzureStackUser${{ github.event.inputs.regionName }}" \
#    --endpoint-resource-manager "https://management.${{ github.event.inputs.regionName }}.${{ github.event.inputs.fqdn }}" \
#    --suffix-storage-endpoint ".${{ github.event.inputs.regionName }}.${{ github.event.inputs.fqdn }}" \
#    --suffix-keyvault-dns ".vault.${{ github.event.inputs.regionName }}.${{ github.event.inputs.fqdn }}" \
#    --endpoint-active-directory-graph-resource-id "https://graph.windows.net/" \
#    --endpoint-sql-management https://notsupported  \
#    --profile 2019-03-01-hybrid

# subId=$(az account show --subscription <Subscription Name> --query id -o tsv)
# az ad sp create-for-rbac --name "ghRunner1" --role contributor --scopes /subscriptions/${subId} --sdk-auth

