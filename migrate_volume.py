import configparser
import logging
import os
from datetime import datetime
import openstack 
import paramiko
import time
import math
import sys
import argparse

# Logging configuration
LOG_DIR = "/var/log/myscript"
LOG_FILE = os.path.join(LOG_DIR, "logs.log")

# Create logging directory if doesn't exist
os.makedirs(LOG_DIR, exist_ok=True)

# Logger configuration
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Log format
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# File handler
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.DEBUG)

# Console handler
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
stream_handler.setLevel(logging.INFO)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)

def log_step(step):
    logger.info(f"STEP: {step}")
    logger.debug(f"Step details: {datetime.utcnow().isoformat()} - {step}")

def get_compute_host(conn, instance_uuid):
    try:
        log_step("Getting compute host information")
        server = conn.compute.get_server(instance_uuid)
        server.to_dict()
        compute_host = server.host
        if not compute_host:
            compute_host = server.get("OS-EXT-SRV-ATTR:host")
        if not compute_host:
            compute_host = getattr(server, "OS-EXT-SRV-ATTR:host", None)
        if not compute_host:
            compute_host = server.hypervisor_hostname
        if not compute_host:
            raise Exception("Compute host not found for instance")
        logger.info(f"Instance running on compute node: {compute_host}")
        return compute_host
    except Exception as e:
        logger.error(f"Error getting compute host: {str(e)}")
        raise

def connect_openstack_from_yaml(config_file, cloud_name):
    try:
        log_step(f"Loading cloud config from {config_file}")
        
        # Verify file existence
        if not os.path.exists(config_file):
            raise Exception(f"Config file {config_file} not found")

        # Debug: Print config file contents
        with open(config_file, 'r') as f:
            logger.debug(f"Config file contents:\n{f.read()}")

        # Load the cloud configuration
        config_loader = openstack.config.loader.OpenStackConfig(config_files=[config_file])
        available_clouds = config_loader.get_all()

        if not available_clouds:
            raise Exception(f"No clouds found in {config_file}")

        logger.debug(f"Available clouds: {[cloud.name for cloud in available_clouds]}")

        # Verify the requested cloud exists
        if cloud_name not in [cloud.name for cloud in available_clouds]:
            raise Exception(f"Cloud {cloud_name} not found in {config_file}")

        # Connect to OpenStack
        log_step(f"Connecting to cloud {cloud_name}")
        conn = openstack.connect(
            cloud=cloud_name,
            config_files=[config_file],
            auth_type='password'
        )
        
        # Verify connection
        log_step("Validating OpenStack connection")
        conn.authorize()
        return conn
    except Exception as e:
        logger.error(f"Connection failed for cloud {cloud_name}: {str(e)}")
        raise

#def connect_openstack_from_yaml(config_file, cloud_name=None):
#    """Loads the first available cloud from a given clouds.yaml file."""
#    config_loader = openstack.config.loader.OpenStackConfig(config_files=[config_file])
#    available_clouds = config_loader.get_all()
#
#    if not available_clouds:
#        raise Exception(f"No clouds found in {config_file}!")
#
#    # Log all available clouds for debugging
#    print(f"DEBUG: Available clouds in {config_file}: {[cloud.name for cloud in available_clouds]}")
#
#    cloud_name = cloud_name or available_clouds[0].name
#    print(f"Using cloud from {config_file}: {cloud_name}")
#
#    cloud_config = config_loader.get_one(cloud=cloud_name)
#    print(f"DEBUG: Cloud config for {cloud_name}: {cloud_config}")
#
#    # Ensure auth_url exists
#    if not cloud_config.auth.get("auth_url"):
#        raise Exception(f"Missing 'auth_url' for cloud {cloud_name}")
#    # Attempt to connect directly using config_files
#    try:
#        print(f"Connecting to cloud {cloud_name} using config file {config_file}")
#        return openstack.connect(cloud=cloud_name, config_files=[config_file])
#    except Exception as e:
#        print(f"ERROR: Connection failed for cloud {cloud_name}, error: {e}")
#        raise

def wait_for_status(resource, status, fetch_func, timeout=300):
    start = time.time()
    log_step(f"Waiting for status {status} on resource {resource.id}")
    
    while time.time() - start < timeout:
        try:
            current = fetch_func(resource.id)
            logger.debug(f"Current status: {current.status}")
            
            if current.status == status:
                logger.info(f"Resource {resource.id} reached status {status}")
                return current
            if current.status == 'error':
                logger.error(f"Resource entered error state: {current}")
                raise Exception(f"Resource error: {current}")
                
            time.sleep(10)
        except Exception as e:
            logger.error(f"Error checking status: {str(e)}")
            raise
    
    logger.error(f"Timeout waiting for {status} on {resource.id}")
    raise Exception(f"Timeout waiting for {status}")

'''
Stops and locks the instance.
This function first stops the instance (if it is not already shutoff),
waits for it to reach SHUTOFF status, and then locks the instance.
'''
def stop_instance(conn, instance_uuid):
    try:
        log_step(f"Stopping instance {instance_uuid}")
        server = conn.compute.find_server(instance_uuid)
        
        if not server:
            logger.error(f"Instance {instance_uuid} not found")
            raise Exception("Instance not found")
            
        logger.debug(f"Current instance status: {server.status}")
        server = conn.compute.get_server(server.id)
        
        if server.status != 'SHUTOFF':
            logger.info(f"Stopping instance...")
            conn.compute.stop_server(server)
            server = wait_for_status(server, 'SHUTOFF', conn.compute.get_server)
        else:
            logger.info("Instance already in SHUTOFF state")
        # Lock the instance after shutdown
        log_step(f"Locking instance {instance_uuid}")
        conn.compute.lock_server(server)
        logger.info("Instance locked successfully")
        return server
    except Exception as e:
        logger.error(f"Error stopping and locking instance: {str(e)}")
        raise

def get_ssh_client(hostname, username, key_path):
    try:
        log_step(f"Connecting to SSH: {username}@{hostname}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username, key_filename=key_path)
        logger.info("SSH connection established")
        return client
    except Exception as e:
        logger.error(f"SSH connection failed: {str(e)}")
        raise

def get_qcow2_virtual_size(ssh_client, instance_uuid, container_name):
    """Get the virtual size of the qcow2 disk image."""
    try:
        log_step("Checking qcow2 virtual disk size")
        cmd = (
            f"sudo podman exec {container_name} qemu-img info "
            f"/var/lib/nova/instances/{instance_uuid}/disk | grep 'virtual size'"
        )
        logger.debug(f"Executing command: {cmd}")
        _, stdout, stderr = ssh_client.exec_command(cmd)
        
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_msg = stderr.read().decode()
            logger.error(f"Failed to get qcow2 size: {error_msg}")
            raise Exception("qcow2 size check failed")
        
        size_str = stdout.read().decode().split('(')[1].split()[0]
        size_bytes = int(size_str)
        logger.info(f"qcow2 virtual size: {size_bytes} bytes")
        return size_bytes
    except Exception as e:
        logger.error(f"Error getting qcow2 size: {str(e)}")
        raise

def get_available_space(ssh_client, instance_uuid, container_name):
    """Check available disk space in the container's instance directory."""
    try:
        log_step("Checking available disk space in container")
        path = f"/var/lib/nova/instances/{instance_uuid}/"
        cmd = (
            f"sudo podman exec {container_name} df -B1 --output=avail {path} "
            "| tail -n 1"
        )
        logger.debug(f"Executing command: {cmd}")
        _, stdout, stderr = ssh_client.exec_command(cmd)
        
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_msg = stderr.read().decode()
            logger.error(f"Space check failed: {error_msg}")
            raise Exception("Available space check failed")
        
        available_bytes = int(stdout.read().decode().strip())
        logger.info(f"Available space: {available_bytes} bytes")
        return available_bytes
    except Exception as e:
        logger.error(f"Error checking available space: {str(e)}")
        raise

def convert_disk(ssh_client, instance_uuid, container_name):
    try:
        log_step(f"Converting disk for instance {instance_uuid}")
        cmd = (
            f"sudo podman exec {container_name} qemu-img convert -f qcow2 -O raw "
            f"/var/lib/nova/instances/{instance_uuid}/disk "
            f"/var/lib/nova/instances/{instance_uuid}/disk.raw"
        )
        
        logger.debug(f"Executing command: {cmd}")
        _, stdout, stderr = ssh_client.exec_command(cmd)
        
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_msg = stderr.read().decode()
            logger.error(f"Conversion failed with status {exit_status}: {error_msg}")
            raise Exception(f"Conversion error: {error_msg}")
            
        logger.info("Disk conversion successful")
    except Exception as e:
        logger.error(f"Error converting disk: {str(e)}")
        raise

def get_disk_size(ssh_client, instance_uuid):
    try:
        log_step("Getting disk size")
        cmd = f"sudo podman exec nova_libvirt qemu-img info /var/lib/nova/instances/{instance_uuid}/disk.raw | grep 'virtual size'"
        
        logger.debug(f"Executing command: {cmd}")
        _, stdout, stderr = ssh_client.exec_command(cmd)
        
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_msg = stderr.read().decode()
            logger.error(f"Size check failed: {error_msg}")
            raise Exception("Size check failed")
            
        size_str = stdout.read().decode().split('(')[1].split()[0]
        size_gb = math.ceil(int(size_str) / 10**9)
        logger.info(f"Detected disk size: {size_gb}GB")
        return size_gb
    except Exception as e:
        logger.error(f"Error getting disk size: {str(e)}")
        raise

def create_volume(conn, size, volume_type):
    try:
        log_step(f"Creating new volume of size {size}GB type {volume_type}")
        vol = conn.block_storage.create_volume(size=size, volume_type=volume_type)
        logger.info(f"Volume created: {vol.id}")
        return wait_for_status(vol, 'available', conn.block_storage.get_volume)
    except Exception as e:
        logger.error(f"Error creating volume: {str(e)}")
        raise

def copy_ceph_configs(ssh_client, container_name):
    """Copy Ceph configs from local machine to container"""
    try:
        ceph = ceph_config['ceph']

        # Copy ceph.conf
        local_conf = ceph['ceph_cp_conf_path']
        remote_conf = f"/tmp/{os.path.basename(local_conf)}"

        # Use SCP to transfer file
        scp = paramiko.SFTPClient.from_transport(ssh_client.get_transport())
        scp.put(local_conf, remote_conf)

        # Move file into container
        cmd = f"sudo podman cp {remote_conf} {container_name}:/etc/ceph/ceph.conf"
        ssh_client.exec_command(cmd)

        # Repeat for keyring
        local_keyring = ceph['keyring_cp_path']
        remote_keyring = f"/tmp/{os.path.basename(local_keyring)}"
        scp.put(local_keyring, remote_keyring)
        cmd = f"sudo podman cp {remote_keyring} {container_name}:/etc/ceph/ceph.client.cinder.keyring"
        ssh_client.exec_command(cmd)

        logger.info("Ceph configs copied to container")
    except Exception as e:
        logger.error(f"Failed to copy Ceph configs: {str(e)}")
        raise

def manage_ceph_image(ssh_client, volume_uuid, action):
    try:
        ceph = ceph_config['ceph']
        log_step(f"Performing Ceph operation: {action}")
        
        if "import" in action:
            cmd = f"sudo podman exec nova_libvirt rbd -c {ceph['ceph_conf_path']} -k {ceph['keyring_path']} --id {ceph['client_id']} {action} {ceph['pool_name']}/volume-{volume_uuid}"
        else:
            cmd = f"sudo podman exec nova_libvirt rbd -c {ceph['ceph_conf_path']} -k {ceph['keyring_path']} --id {ceph['client_id']} {action} {ceph['pool_name']}/volume-{volume_uuid}"
        
        logger.debug(f"Executing Ceph command: {cmd}")
        _, stdout, stderr = ssh_client.exec_command(cmd)
        
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0 and "No such file" not in stderr.read().decode():
            error_msg = stderr.read().decode()
            logger.error(f"Ceph operation failed: {error_msg}")
            raise Exception(f"Ceph error: {error_msg}")
            
        logger.info("Ceph operation completed")
    except Exception as e:
        logger.error(f"Error in Ceph operation: {str(e)}")
        raise

def main(instance_uuid, volume_type, flavor_id):
    logger.info(f"Starting migration for instance {instance_uuid}")
    
    try:
        # Define paths to your clouds.yaml files
        cloud_yaml = "/root/script/clouds.yaml"
        
        # Operation on source cloud
        log_step("Connecting to source cluster")
        src_conn = connect_openstack_from_yaml(cloud_yaml, cloud_name="kolla-admin-src")
        
        log_step("Stopping instance")
        server = stop_instance(src_conn, instance_uuid)
        compute_host = get_compute_host(src_conn, instance_uuid)

        if not compute_host:
            raise Exception("Could not determine compute host from instance data")
            
        logger.info(f"Using compute host: {compute_host}")
        
        log_step("Establishing SSH connection")
        ssh = get_ssh_client(
            compute_host,
            openstack_config['source']['ssh_user'],
            openstack_config['source']['ssh_key_path']
        )
        
        try:
            # container_name = openstack_config['source'].get('libvirt_container', 'nova_libvirt')
            container_name = 'nova_libvirt'
            logger.info(f"Using libvirt container: {container_name}")
            
            # Check disk space before conversion
            log_step("Validating disk space for conversion")
            qcow2_size = get_qcow2_virtual_size(ssh, instance_uuid, container_name)
            available_space = get_available_space(ssh, instance_uuid, container_name)
            
            # Add 10% buffer to required space
            required_space = qcow2_size * 1.1
            if available_space < required_space:
                logger.error(
                    f"Insufficient space: {available_space} bytes available, "
                    f"{required_space} bytes required"
                )
                raise Exception("Insufficient disk space for conversion")

            log_step("Converting disk format")
            convert_disk(ssh, instance_uuid, container_name)
            
            log_step("Calculating disk size")
            size = get_disk_size(ssh, instance_uuid)
            
            # Destination cloud - operations
            log_step("Connecting to destination cluster")
            dest_conn = connect_openstack_from_yaml(cloud_yaml, cloud_name="kolla-admin-dst")
            
            log_step("Creating new volume")
            vol = create_volume(dest_conn, size, volume_type)
            
            # Ceph image handler
            log_step("Preparing Ceph image")
            copy_ceph_configs(ssh, container_name)
            manage_ceph_image(ssh, vol.id, 'rm')
            
            log_step("Importing to Ceph")
            manage_ceph_image(
                ssh, 
                vol.id, 
                f"import /var/lib/nova/instances/{instance_uuid}/disk.raw --dest"
            )
            
            log_step("Setting bootable flag")
            dest_conn.block_storage.set_volume_bootable_status(vol, True)
            logger.info(f"Successfully migrated volume: {vol.id}")

            # ----- NEW PART: create an instance on destination cloud -----
            log_step("Creating new instance on destination cloud from migrated volume")
            # Retrieve source instance configuration (networks, security groups, etc.)
            orig_instance = src_conn.compute.get_server(instance_uuid)

            # Prepare network configuration - iterate through network name and its addresses
            networks_config = []
            for net_name, addresses in orig_instance.addresses.items():
                dest_net = dest_conn.network.find_network(net_name)
                if not dest_net:
                    logger.error(f"Network {net_name} not found in destination cloud")
                    raise Exception(f"Network {net_name} not found in destination cloud")
                
                fixed_ip = None
                for address in addresses:
                    if address['version'] == 4:
                        fixed_ip = address['addr']
                        break

                net_config = {"uuid": dest_net.id}
                if fixed_ip:
                    net_config["fixed_ip"] = fixed_ip
                networks_config.append(net_config)
    
            # Prepare security groups by their names. If not available, default is used.
            sec_groups_config = []
            if hasattr(orig_instance, 'security_groups'):
                for sg in orig_instance.security_groups:
                    sec_groups_config.append({"name": sg['name']})
            else:
                sec_groups_config.append({"name": "default"})
            
            # Preserve original SSH key configuration - TODO: currently removed below if it is not handling None value
            key_name = orig_instance.key_name
            
            log_step("Launching new instance on destination using boot from volume")
            new_server = dest_conn.compute.create_server(
                name=orig_instance.name,
                flavor_id=flavor_id,
                networks=networks_config,
                security_groups=sec_groups_config,
                block_device_mapping_v2=[{
                    "boot_index": 0,
                    "uuid": vol.id,
                    "source_type": "volume",
                    "destination_type": "volume",
                    "delete_on_termination": True
                }]
            )
            log_step("Waiting for new instance to become ACTIVE")
            new_server = wait_for_status(new_server, 'ACTIVE', dest_conn.compute.get_server)
            logger.info(f"New instance launched successfully: {new_server.id}")
            # ----- END of NEW PART -----
            
        finally:
            log_step("Closing SSH connection")
            ssh.close()
            
    except Exception as e:
        logger.exception("Critical error during migration")
        raise
    
    logger.info("Migration completed successfully")

if __name__ == "__main__":
    try:
        # Configuration init
        openstack_config = configparser.ConfigParser()
        openstack_config.read('openstack_config.ini')
        
        ceph_config = configparser.ConfigParser()
        ceph_config.read('ceph_config.ini')
        
        # Arg Parser
        parser = argparse.ArgumentParser()
        parser.add_argument('instance_uuid', help='UUID of migrated instance')
        parser.add_argument('volume_type', help='Volume type for migrated volume')
        parser.add_argument('flavor', help='Flavor ID for the new VM on the destination cloud')

        args = parser.parse_args()
        
        main(args.instance_uuid, args.volume_type, args.flavor)
        
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
        sys.exit(1)
