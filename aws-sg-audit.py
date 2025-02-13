#!/usr/bin/env python3
"""AWS Security Group Dependency Analyzer

This script analyzes AWS security group dependencies and helps identify obsolete security groups
or those only used by specific services. It uses boto3 and follows modern Python best practices.
"""

import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from queue import Queue
from typing import Dict, List, Optional, Set

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SecurityGroupObject:
    """Class to hold objects which use security groups."""
    sg_id: str
    service: str
    resource_id: str
    name: Optional[str] = None

    def __str__(self) -> str:
        """String representation of the security group object."""
        if self.name:
            return f"{self.service}: {self.resource_id} ({self.name})"
        return f"{self.service}: {self.resource_id}"


class SecurityGroupDependencies:
    """Analyzes AWS security group dependencies."""

    def __init__(self, region_name: str):
        """Initialize the analyzer for a specific region.

        Args:
            region_name: AWS region name

        Raises:
            SystemExit: If region is invalid or credentials are incorrect
        """
        self.region = region_name
        self.sg_by_id: Dict[str, dict] = {}
        self.sg_by_name: Dict[str, str] = {}
        self.queue: Queue = Queue()

        # List of services to check
        self.service_list = ["ec2", "elb", "rds", "redshift", "elasticache", "eni"]

        try:
            # Initialize boto3 session
            self.session = boto3.Session(region_name=region_name)
            self.ec2 = self.session.client('ec2')

            # Validate region
            valid_regions = [region['RegionName'] for region in
                             self.ec2.describe_regions()['Regions']]
            if region_name not in valid_regions:
                logger.error("Invalid region name: %s", region_name)
                logger.info("Valid regions: %s", ", ".join(valid_regions))
                sys.exit(1)

            # Get all security groups
            self.sgs = self.ec2.describe_security_groups()['SecurityGroups']

        except (BotoCoreError, ClientError) as e:
            logger.error("AWS API error: %s", str(e))
            sys.exit(1)

        # Initialize data using thread pool
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.prepare_sg)]
            futures.extend([
                executor.submit(self.process_service, service)
                for service in self.service_list
            ])

            # Wait for all tasks to complete
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    logger.error("Error processing service: %s", str(e))

        # Process queued objects
        while not self.queue.empty():
            obj = self.queue.get()
            self.sg_by_id[obj.sg_id]["objects"].add(obj)

    def prepare_sg(self) -> None:
        """Prepare security group data structures."""
        for sg in self.sgs:
            sg_id = sg['GroupId']
            self.sg_by_name[sg['GroupName']] = sg_id

            if sg_id not in self.sg_by_id:
                self.sg_by_id[sg_id] = {
                    "dependencies": set(),
                    "objects": set(),
                    "name": sg['GroupName']
                }

            # Process inbound rules
            for rule in sg.get('IpPermissions', []):
                for group in rule.get('UserIdGroupPairs', []):
                    if 'GroupId' not in group:
                        continue
                    target_sg_id = group['GroupId']
                    if target_sg_id not in self.sg_by_id:
                        self.sg_by_id[target_sg_id] = {
                            "dependencies": set(),
                            "objects": set()
                        }
                    self.sg_by_id[target_sg_id]["dependencies"].add(sg_id)

    def process_service(self, service: str) -> None:
        """Process a specific AWS service.

        Args:
            service: Name of the AWS service to process
        """
        try:
            method = getattr(self, f"list_{service}_sg")
            method()
        except AttributeError:
            logger.warning("Service %s not implemented", service)
        except Exception as e:
            logger.error("Error processing %s: %s", service, str(e))

    def list_eni_sg(self) -> None:
        """List security groups used by ENIs."""
        paginator = self.ec2.get_paginator('describe_network_interfaces')
        for page in paginator.paginate():
            for eni in page['NetworkInterfaces']:
                name = next((tag['Value'] for tag in eni.get('Tags', [])
                             if tag['Key'] == 'Name'), "")
                for group in eni.get('Groups', []):
                    self.queue.put(SecurityGroupObject(
                        group['GroupId'], 'eni', eni['NetworkInterfaceId'], name
                    ))

    def list_ec2_sg(self) -> None:
        """List security groups used by EC2 instances."""
        paginator = self.ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    name = next((tag['Value'] for tag in instance.get('Tags', [])
                                 if tag['Key'] == 'Name'), "")
                    for group in instance.get('SecurityGroups', []):
                        self.queue.put(SecurityGroupObject(
                            group['GroupId'], 'ec2', instance['InstanceId'], name
                        ))

    def list_elb_sg(self) -> None:
        """List security groups used by ELBs."""
        elb = self.session.client('elbv2')
        paginator = elb.get_paginator('describe_load_balancers')
        for page in paginator.paginate():
            for lb in page['LoadBalancers']:
                for group in lb.get('SecurityGroups', []):
                    self.queue.put(SecurityGroupObject(
                        group, 'elb', lb['LoadBalancerName']
                    ))

    def list_rds_sg(self) -> None:
        """List security groups used by RDS instances."""
        rds = self.session.client('rds')
        paginator = rds.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for instance in page['DBInstances']:
                for group in instance.get('VpcSecurityGroups', []):
                    self.queue.put(SecurityGroupObject(
                        group['VpcSecurityGroupId'], 'rds',
                        instance['DBInstanceIdentifier']
                    ))

    def list_redshift_sg(self) -> None:
        """List security groups used by Redshift clusters."""
        redshift = self.session.client('redshift')
        paginator = redshift.get_paginator('describe_clusters')
        for page in paginator.paginate():
            for cluster in page['Clusters']:
                for group in cluster.get('VpcSecurityGroups', []):
                    self.queue.put(SecurityGroupObject(
                        group['VpcSecurityGroupId'], 'redshift',
                        cluster['ClusterIdentifier']
                    ))

    def list_elasticache_sg(self) -> None:
        """List security groups used by ElastiCache clusters."""
        elasticache = self.session.client('elasticache')
        paginator = elasticache.get_paginator('describe_cache_clusters')
        for page in paginator.paginate():
            for cluster in page['CacheClusters']:
                for group in cluster.get('SecurityGroups', []):
                    self.queue.put(SecurityGroupObject(
                        group['SecurityGroupId'], 'elasticache',
                        cluster['CacheClusterId']
                    ))

    def show_obsolete_sg(self, show_list: bool = False) -> None:
        """Show security groups not used by any service.

        Args:
            show_list: If True, show only group IDs and names
        """
        obsolete = [sg_id for sg_id, data in self.sg_by_id.items()
                    if not data["objects"]]

        if obsolete:
            print(f"\nFound {len(obsolete)} obsolete security groups:")
            for sg_id in obsolete:
                if show_list:
                    print(self._format_sg(sg_id))
                else:
                    print(f"\n{'-' * 70}")
                    print(f"Security Group: {self._format_sg(sg_id)}")
                    print(f"Status: Not used by any supported service ({', '.join(self.service_list)})")
                    # Check if it has any dependencies
                    if self.sg_by_id[sg_id]["dependencies"]:
                        print("Dependencies: This security group is referenced by other security groups:")
        else:
            logger.info("\nNo obsolete security groups found")

    def show_eni_only_sg(self, show_list: bool = False) -> None:
        """Show security groups only used by ENIs.

        Args:
            show_list: If True, show only group IDs and names
        """
        eni_only = [
            sg_id for sg_id, data in self.sg_by_id.items()
            if data["objects"] and all(obj.service == "eni" for obj in data["objects"])
        ]

        if eni_only:
            logger.info("\nSecurity groups used only by ENIs:\n")
            if show_list:
                for sg_id in eni_only:
                    print(self._format_sg(sg_id))
            else:
                for sg_id in eni_only:
                    self.show_sg_details(sg_id)
        else:
            logger.info("\nNo ENI-only security groups found")

    def show_sg_details(self, sg_id: str, show_list: bool = False) -> None:
        """Show details for a specific security group.

        Args:
            sg_id: Security group ID or name
            show_list: If True, show only group ID and name
        """
        if not sg_id:
            for group_id in self.sg_by_id:
                self.show_sg_details(group_id, show_list)
            return

        # Resolve security group ID
        if sg_id in self.sg_by_id:
            group_id = sg_id
        elif sg_id in self.sg_by_name:
            group_id = self.sg_by_name[sg_id]
        else:
            logger.error("\nCannot find security group: %s\n", sg_id)
            return

        if show_list:
            print(self._format_sg(group_id))
        else:
            print("\n" + "-" * 70)
            self._show_dependencies(group_id, [], [])
            self._show_objects(group_id)

    def _show_dependencies(self, sg_id: str, previous: List[str],
                           indent: List[bool]) -> None:
        """Show security group dependencies recursively.

        Args:
            sg_id: Security group ID
            previous: List of previously processed group IDs
            indent: List of indent levels
        """
        if not previous:
            print(self._format_sg(sg_id), end="")
        else:
            pre = "".join("│  " if x else "   " for x in indent[:-1])
            pre += "├──" if indent[-1] else "└──"
            print(f"{pre} {self._format_sg(sg_id)}", end="")

        if sg_id in previous:
            print(" ** loop")
            return
        print()

        deps = list(self.sg_by_id[sg_id]["dependencies"])
        for i, dep in enumerate(deps):
            self._show_dependencies(dep, previous + [sg_id],
                                    indent + [i < len(deps) - 1])

    def _show_objects(self, sg_id: str) -> None:
        """Show objects using a security group.

        Args:
            sg_id: Security group ID
        """
        objects = self.sg_by_id[sg_id]["objects"]
        if not objects:
            logger.info("\nNot used by any %s service",
                        "/".join(self.service_list))
        else:
            logger.info("\nUsed by:")
            for obj in sorted(objects,
                              key=lambda x: f"{x.service}{x.name or ''}{x.resource_id}"):
                print(f"  {obj}")

    def _format_sg(self, sg_id: str) -> str:
        """Format security group information.

        Args:
            sg_id: Security group ID

        Returns:
            Formatted string with security group details
        """
        name = self.sg_by_id[sg_id].get("name", "N/A")
        return f"{sg_id} ({name})"


def main() -> None:
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Analyze AWS security group dependencies",
        epilog="""
        Please configure your AWS credentials using one of these methods:
        1. AWS CLI: aws configure
        2. Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
        3. IAM role attached to EC2 instance
        4. Credentials file: ~/.aws/credentials

        For more information, visit:
        https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html
        """
    )

    parser.add_argument(
        "--region",
        required=True,
        help="AWS region to analyze"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Only output group ID/name"
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--obsolete",
        action="store_true",
        help="Show security groups not used by any service"
    )
    group.add_argument(
        "--eni-only",
        action="store_true",
        help="Show security groups only used by ENIs"
    )

    parser.add_argument(
        "security_group",
        nargs="?",
        default="",
        help="Security group ID or name (optional)"
    )

    args = parser.parse_args()

    try:
        analyzer = SecurityGroupDependencies(args.region)

        if args.obsolete:
            analyzer.show_obsolete_sg(show_list=args.list)
        elif args.eni_only:
            analyzer.show_eni_only_sg(show_list=args.list)
        else:
            analyzer.show_sg_details(args.security_group, show_list=args.list)

    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error("Unexpected error: %s", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()