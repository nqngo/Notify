#!/usr/bin/env python
#
# Author: Nhat Q. Ngo (2017)
# A rewritten general purpose tool

import os
import re
import logging
import argparse
import datetime

import keystoneauth1
from novaclient import client as nova_client
from keystoneclient import client as keystone_client

def cli():
  """CLI parameters and help"""
  cli_usage = "Notifies users of an upcoming outage"
  search_usage = "Search for affected hosts in the following instances"
  file_usage = "Get affected instances from file"
  send_usage = "Send all email from a specified outbox"
  debug_usage = "Set logging level to DEBUG"
  subject_usage = "(Optional) Subject of the email"
  file_arg_usage = "File contain list of instances id"
  az_usage = "Only target instances in this availability zone"
  aggregate_usage = "Only target instances in the following aggregates"
  hosts_usage = "Only target instances from the following hosts (eg. qh2-rcc[10-99])"
  start_time_usage = "Outage start time (e.g. \"09:00 25-06-2015\")"
  status_usage = "Only consider instances with given status"
  duration_usage = "Duration of outage in hours"
  timezone_usage = "Timezone (e.g. AEDT)"
  template_usage = "Name of template to use"
  outbox_usage = "Path to outbox folder containg emails"
  recipient_usage = "Send a SINGLE test email to the recipient"
  smtp_usage = "SMTP server to use, defaults to localhost"

  parser = argparse.ArgumentParser(description=cli_usage)
  subparsers = parser.add_subparsers(dest="command")

  parser.add_argument("--debug", action="store_true", help=debug_usage)
  
  # Search sub-command
  parser_search = subparsers.add_parser("SEARCH", help=search_usage)
  parser_search.add_argument("--subject", help=subject_usage)
  parser_search.add_argument("--status", action="append", help=status_usage)
  parser_search.add_argument("-tz", "--timezone", default="AEDT", help=timezone_usage)
  parser_search.add_argument("-s", "--start_time", type=get_datetime, help=start_time_usage)
  parser_search.add_argument("-d", "--duration", type=int, help=duration_usage)
  # parser_search.add_argument("-t", "--template", required=True, help=template_usage)
  search_by = parser_search.add_mutually_exclusive_group()
  search_by.add_argument("-z", "--zone", action="append", help=az_usage)
  search_by.add_argument("--hosts", type=parse_nodes, help=hosts_usage)
  search_by.add_argument("-ag", "--aggregate", action="append", help=aggregate_usage)

  # Read from file
  parser_file = subparsers.add_parser("FILE", help=file_usage)
  parser_file.add_argument("file", type=str, help=file_arg_usage)
  parser_file.add_argument("--subject", help=subject_usage)

  # Sending sub-command
  parser_send = subparsers.add_parser("SEND", help=send_usage)
  parser_send.add_argument("outbox", help=outbox_usage)
  parser_send.add_argument("-tr", "--test_recipient", action="append", help=recipient_usage)
  parser_send.add_argument("-p", "--smtp_server", default="127.0.0.1", help=smtp_usage)

  return parser.parse_args() 


def get_datetime(dt_string):
  """Parse the datetime input"""
  return datetime.datetime.strptime(dt_string, "%H:%M %d-%m-%Y")


def get_session():
  """Get the auth session for Openstack API client."""
  url = os.environ.get("OS_AUTH_URL")
  username = os.environ.get("OS_USERNAME")
  user_domain_name = "Default"
  password = os.environ.get("OS_PASSWORD")
  tenant = os.environ.get("OS_TENANT_NAME")
  project_domain_name = "Default"
  
  if not url or not username or not password or not tenant:
    raise AuthenticationError("Have you source your admin.rc credential?")

  auth = keystoneauth1.identity.Password(username=username,
                                        password=password,
                                        project_name=tenant,
                                        auth_url=url,
                                        user_domain_name=user_domain_name,
                                        project_domain_name=project_domain_name)
  return keystoneauth1.session.Session(auth=auth)


def parse_dash(range_str):
  """Unpack the dash syntax into a set of number"""
  hosts = range_str.split("-")
  return range(int(hosts[0]), int(hosts[1]) + 1) if len(hosts) > 1 else [range_str]


def parse_nodes(nodes):
  """Parse list syntax (eg. qh2-rcc[01-10,13])"""

  # Parse qh2-rcc5,qh2-rcc6,qh2-rcc7 syntax
  nodes = re.split(r",\s*(?![^\[\]]*\])", nodes)

  if len(nodes) > 1:
    nodes = set(host for hosts in nodes for host in parse_nodes(hosts))
  else:
    # Parse qh2-rcc[112-114,115] syntax
    match = re.search(r"(.*?)\[(.*?)\](.*)", nodes[0])
    if match:
      host_ranges = [host for hosts in parse_nodes(match.group(2))
                          for host in parse_dash(hosts)]
      nodes = set("%s%s%s" % (match.group(1), host, match.group(3)) for host in host_ranges)
  return nodes


def get_instances_by_hosts(nova, statuses, hosts):
  """Get instances from nova client from the following zone and statuses"""
  opts = { 'all_tenants': True }
  for host in hosts:
    opts['host'] = host
    # Get all instances in the hosts
    if not statuses:
      for server in nova.servers.list(search_opts=opts):
        yield server
    # Filter instances by statuses
    else:
      for status in statuses:
        opts['status'] = status
        for server in nova.servers.list(search_opts=opts):
          yield server


def get_instances_by_file(nova, idfile):
  """Get instances from nova client where name appear in the given file"""
  with open(idfile, 'r') as servers:
    for server in servers:
        yield nova.servers.get(server.strip())


def get_hosts_by_aggregates(nova, aggregates):
  """Fetch hosts by aggregates"""
  return set(host for aggregate in nova.aggregates.list()
                  for host in aggregate.hosts
                  if aggregate.name in aggregates)


def get_hosts_by_zones(nova, zones):
  """Get all hosts in the following zones"""
  return set(host for aggregate in nova.aggregates.list()
                  for host in aggregate.hosts
                  if u"availability_zone" in aggregate.metadata and
                     aggregate.metadata[u"availability_zone"] in zones)


def populate_instances_details(keystone, instances):
  """Populate the instances with projects and users details"""
  # Keep a dictionary of users and projects so we don't keep making 
  # multiple keystone call
  users = {}
  projects = {}
  servers = []

  for server in instances:
    # If a project been processed, use the cached data
    if server.tenant_id not in projects:
      projects[server.tenant_id] = keystone.projects.get(server.tenant_id)
      projects[server.tenant_id].servers = []
      project_users = []
      # Use role_assignments to find all user in the project
      for assignment in keystone.role_assignments.list(project=server.tenant_id):
        if assignment.user["id"] not in users:
          users[assignment.user["id"]] = keystone.users.get(assignment.user["id"])
        project_users.append(users[assignment.user["id"]])
      projects[server.tenant_id].users = set(project_users)

    server.project = projects[server.tenant_id]
    server.users = server.project.users
    projects[server.tenant_id].servers.append(server)
    servers.append(server)

  LOGGER.info("Total number of users affected: %7i user(s)." % len(users))
  LOGGER.info("Total number of projects affected: %4i project(s)." % len(projects))

  return servers

LOGGER = logging.getLogger("notify")

if __name__ == "__main__":
  args = cli()
  
  log_level = logging.INFO
  log_format = "%(asctime)s - %(message)s"

  if args.debug:
    log_level = logging.DEBUG
    log_format = "%(asctime)s %(name)s [%(levelname)-5.5s] - %(message)s"

  logging.basicConfig(format=log_format, level=log_level)
  
  sess = get_session()

  kc = keystone_client.Client(3, session=sess)
  nc = nova_client.Client(2, session=sess)

  if args.command in "SEARCH":
    hosts = args.hosts
    if args.aggregate:
      LOGGER.info("Searching hosts in the following aggregates: [%s]" % ", ".join(args.aggregate))
      hosts = get_hosts_by_aggregates(nc, args.aggregate)
    elif args.zone:
      LOGGER.info("Searching hosts for the following zones: [%s]" % ", ".join(args.zone))
      hosts = get_hosts_by_zones(nc, args.zone)
    
    LOGGER.info("Find instance for the following hosts: [%s]" % ", ".join(hosts))
    if args.status:
      LOGGER.info("With the following status: [%s]" % ", ".join(state.upper() for state in args.status))
    servers = populate_instances_details(kc, get_instances_by_hosts(nc, args.status, hosts))
    #servers = [server for server in get_instances_by_hosts(nc, args.status, hosts)]
    LOGGER.info("Total number of instances affected: %3i instance(s)." % len(servers))
  elif args.command in "FILE":
    servers = [server for server in get_instances_by_file(nc, args.file)]
    populate_instances_details(kc, servers)
    

