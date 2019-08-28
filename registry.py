#!/usr/bin/env python

import requests
import ast
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import copy
import json
import logging
import base64
import re
import pprint
import sys
import os
import argparse
import www_authenticate
import ciso8601
import _strptime
import dateutil.tz
from datetime import timedelta, datetime as dt
from getpass import getpass
from multiprocessing.pool import ThreadPool

# this is a registry manipulator, can do following:
# - list all images (including layers)
# - delete images
# - all except last N images
# - all images and/or tags
#
# run
# registry.py -h
# to get more help
#
# important: after removing the tags, run the garbage collector
# on your registry host:
# docker-compose -f [path_to_your_docker_compose_file] run \
# registry bin/registry garbage-collect \
# /etc/docker/registry/config.yml
#
# or if you are not using docker-compose:
# docker run registry:2 bin/registry garbage-collect \
# /etc/docker/registry/config.yml
#
# for more detail on garbage collection read here:
# https://docs.docker.com/registry/garbage-collection/


# number of image versions to keep
CONST_KEEP_LAST_VERSIONS = 10


# this class is created for testing
class Requests:

    def __init__(self):
        self._bearer_auth_token = None
        self.auth_schemes = []
        self.username = None
        self.password = None

    def _refresh_bearer_auth_token(self, auth, headers):
        oauth = www_authenticate.parse(headers['Www-Authenticate'])
        auth_method = args.auth_method.upper()

        logging.debug('[auth][answer] Auth header:')
        logging.debug(oauth['bearer'])

        request_url = '{0}'.format(oauth['bearer']['realm'])
        query_separator = '?'
        if 'service' in oauth['bearer']:
            request_url += '{0}service={1}'.format(query_separator, oauth['bearer']['service'])
            query_separator = '&'
        if 'scope' in oauth['bearer']:
            request_url += '{0}scope={1}'.format(query_separator, oauth['bearer']['scope'])

        logging.debug('[auth][request] Refreshing auth token: {0} {1}'.format(auth_method, request_url))

        if auth_method == 'GET':
            try_oauth = self._request("get", request_url, auth=auth, headers={'Accept': 'application/json'})
        else:
            try_oauth = self._request("post", request_url, auth=auth, headers={'Accept': 'application/json'})

        try:
            oauth_response = ast.literal_eval(try_oauth._content.decode('utf-8'))
            logging.debug('[auth][request] Response content: {0}'.format(oauth_response))
            token = oauth_response['access_token'] if 'access_token' in oauth_response else oauth_response['token']
        except SyntaxError:
            logging.error('could not acquire token: {0}'.format(try_oauth._content))
            sys.exit(1)

        logging.debug('[auth] token issued: {0}'.format(token))

        self._bearer_auth_token = token

    def init_auth_schemes(self, url, verify):
        """ Updates list of auth schemes(lowcased) if www-authenticate: header exists
             returns None if no header found
             - www-authenticate: basic
             - www-authenticate: bearer
        """
        try_oauth = requests.head(url, verify=verify)

        logging.debug("[auth][registry] Headers: \n{0}".format(try_oauth.headers))

        if 'Www-Authenticate' in try_oauth.headers:
            oauth = www_authenticate.parse(try_oauth.headers['Www-Authenticate'])
            logging.debug('[auth][registry] Auth schemes found:{0}'.format([m for m in oauth]))
            self.auth_schemes = [m.lower() for m in oauth]
        else:
            logging.debug("[auth][registry] No Auth schemes found'")
            self.auth_schemes = []

    def request(self, method, url, **kwargs):
        if 'bearer' in self.auth_schemes:
            auth = (('', '') if self.username in ["", None] else (self.username, self.password))
            res = self._bearer_request(method, url, auth=auth, **kwargs)
        else:
            auth = (None if self.username == "" else (self.username, self.password))
            res = self._request(method, url, auth=auth, **kwargs)
        return res

    @staticmethod
    def _request(method, url, **kwargs):
        res = requests.request(method, url, **kwargs)
        if str(res.status_code)[0] != '2':
            msg = ' \n[error][registry] Request failed'
            msg += '\n[error][registry][request] method {0}: url: {1}'.format(method, res.url)
            msg += '\n[error][registry][request] headers: {0}'.format(res.request.headers)
            msg += '\n[error][registry][request] body: {0}'.format(res.request.body)
            msg += '\n[error][registry][response] status: {0}'.format(res.status_code)
            msg += '\n[error][registry][response] headers: {0}'.format(res.headers)
            msg += '\n[error][registry][response] content: {0}'.format(res.content)
            logging.debug(msg)
        else:
            logging.debug("[registry][request] method {0}: url: {1}: accept".format(method, res.url))
        return res

    def _bearer_request(self, method, url, auth, **kwargs):
        local_kwargs = copy.deepcopy(kwargs)

        if method.upper() == "DELETE":
            local_kwargs["headers"].pop("Accept", None)

        if self._bearer_auth_token:
            local_kwargs['headers']['Authorization'] = 'Bearer {0}'.format(self._bearer_auth_token)

        res = self._request(method, url, **local_kwargs)
        if str(res.status_code)[0] == '2':
            return res

        if res.status_code == 401:
            self._refresh_bearer_auth_token(auth, res.headers)
            local_kwargs['headers']['Authorization'] = 'Bearer {0}'.format(self._bearer_auth_token)
        else:
            return res

        res = self._request(method, url, **local_kwargs)
        return res


def natural_keys(text):
    """
    alist.sort(key=natural_keys) sorts in human order
    http://nedbatchelder.com/blog/200712/human_sorting.html
    (See Toothy's implementation in the comments)
    """

    def __atoi(text):
        return int(text) if text.isdigit() else text

    return [__atoi(c) for c in re.split('(\d+)', text)]


def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    data = data.replace('Bearer ', '')
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'='* (4 - missing_padding)
    return base64.decodestring(data)


def get_error_explanation(context, error_code):
    error_list = {"delete_tag_405": 'You might want to set REGISTRY_STORAGE_DELETE_ENABLED: "true" in your registry',
                  "get_tag_digest_404": "Try adding flag --digest-method=GET"}

    key = "%s_%s" % (context, error_code)

    if key in error_list.keys():
        return(error_list[key])

    return ''


# class to manipulate registry
class Registry:

    # this is required for proper digest processing
    HEADERS = {"Accept":
               "application/vnd.docker.distribution.manifest.v2+json"}

    def __init__(self):
        self.auth_schemes = []
        self.hostname = None
        self.no_validate_ssl = False
        self.http = None
        self.last_error = None
        self.base_path = ''
        self.digest_method = "HEAD"

    def parse_login(self, login):
        if login is not None:

            if ':' not in login:
                self.last_error = "Please provide -l in the form USER:PASSWORD"
                return (None, None)

            self.last_error = None
            (username, password) = login.split(':', 1)
            username = username.strip('"').strip("'")
            password = password.strip('"').strip("'")
            return (username, password)

        return (None, None)

    @staticmethod
    def _create(host, login, no_validate_ssl, base_path='', digest_method="HEAD"):
        r = Registry()

        (username, password) = r.parse_login(login)
        if r.last_error is not None:
            logging.error(r.last_error)
            sys.exit(1)

        r.hostname = host
        r.base_path = base_path + '/'
        r.no_validate_ssl = no_validate_ssl
        r.http = Requests()
        r.http.username = username
        r.http.password = password
        r.digest_method = digest_method
        return r

    @staticmethod
    def create(*args, **kw):
        return Registry._create(*args, **kw)

    def send(self, path, method="GET", headers=None):
        if not headers:
            headers = self.HEADERS

        result = self.http.request(
            method,
            "{0}{1}".format(self.hostname, path),
            headers=headers,
            verify=not self.no_validate_ssl
        )

        if str(result.status_code)[0] == '2':
            self.last_error = None
            return result

        self.last_error = result.status_code
        return None

    def init_auth_schemes(self):
        # Updates list of auth schemes for the registry
        catalog_path = "/v2/{0}_catalog".format(self.base_path)
        self.http.init_auth_schemes('{0}{1}'.format(self.hostname, catalog_path), verify=not self.no_validate_ssl)

    def list_images(self):
        result = self.send('/v2/{0}_catalog?n=10000'.format(self.base_path),
                           headers={"Accept": "application/json"})
        if result is None:
            return []

        return json.loads(result.text)['repositories']

    def list_tags(self, image_name):
        result = self.send("/v2/{0}{1}/tags/list".format(self.base_path, image_name),
                           headers={"Accept": "application/json"})
        if result is None:
            return []

        try:
            tags_list = json.loads(result.text)['tags']
        except ValueError:
            self.last_error = "list_tags: invalid json response"
            return []

        if tags_list is not None:
            tags_list.sort(key=natural_keys)

        return tags_list

    # def list_tags_like(self, tag_like, args_tags_like):
    #     for tag_like in args_tags_like:
    #         print("tag like: {0}".format(tag_like))
    #         for tag in all_tags_list:
    #             if re.search(tag_like, tag):
    #                 print("Adding {0} to tags list".format(tag))

    def get_tag_digest(self, image_name, tag):
        image_headers = self.send("/v2/{0}{1}/manifests/{2}".format(
            self.base_path, image_name, tag), method=self.digest_method)

        if image_headers is None:
            logging.warning("  tag digest not found: {0}.".format(self.last_error))
            logging.warning(get_error_explanation("get_tag_digest", self.last_error))
            return None

        tag_digest = image_headers.headers['Docker-Content-Digest']

        return tag_digest

    def delete_tag(self, image_name, tag, dry_run, tag_digests_to_ignore):

        def delete(registry, name, manifest):
            url = "/v2/{0}{1}/manifests/{2}".format(registry.base_path, name, manifest)
            delete_result = registry.send(url, method="DELETE")
            if delete_result is None:
                logging.warning("delete failed on {0}, error: {1}".format(url, registry.last_error))
                logging.warning(get_error_explanation("delete_tag", registry.last_error))
            return delete_result

        if dry_run:
            logging.info("would delete image {0} tag {1}".format(image_name, tag))
            return False

        # In some cases the tag itself is the name of the manifest
        # Code below should work in Artifactory, but may not work in dockerhub
        # as there is no official docker API for deleting tags, but not manifests
        # See: https://docs.docker.com/registry/spec/api/#deleting-an-image
        delete_result_tag = delete(self, image_name, tag)
        if delete_result_tag:
            logging.info("done deleting image {0} tag {1}".format(image_name, tag))
            return True

        # Delete on the tag itself has failed, need to delete the digest
        tag_digest = self.get_tag_digest(image_name, tag)
        if tag_digest is None:
            return False

        if tag_digest in tag_digests_to_ignore:
            logging.warning("Digest {0} for tag {1} will be ignored: {2}"
                            .format(tag_digest, tag, tag_digests_to_ignore[tag_digest]))
            return True

        delete_result_digest = delete(self, image_name, tag_digest)
        if not delete_result_digest:
            return False

        tag_digests_to_ignore.setdefault(tag_digest, {})
        tag_digests_to_ignore[tag_digest].setdefault("reason", "deleted")
        tag_digests_to_ignore[tag_digest].setdefault("tags", [])
        tag_digests_to_ignore[tag_digest]["tags"].append(tag)

        logging.info("done deleting image {0} tag {1}".format(image_name, tag))
        return True

    def list_tag_layers(self, image_name, tag):
        layers_result = self.send("/v2/{0}{1}/manifests/{2}".format(
            self.base_path, image_name, tag))

        if layers_result is None:
            logging.warning("error {0}".format(self.last_error))
            return []

        json_result = json.loads(layers_result.text)
        if json_result['schemaVersion'] == 1:
            layers = json_result['fsLayers']
        else:
            layers = json_result['layers']

        return layers

    def get_tag_config(self, image_name, tag):
        config_result = self.send(
            "/v2/{0}{1}/manifests/{2}".format(self.base_path, image_name, tag))

        if config_result is None:
            logging.warning("  tag digest not found: {0}".format(self.last_error))
            return []

        json_result = json.loads(config_result.text)
        if json_result['schemaVersion'] == 1:
            logging.error("Docker schemaVersion 1 isn't supported for deleting by age now")
            tag_config = []
        else:
            tag_config = json_result['config']

        return tag_config

    def get_image_age(self, image_name, image_config):
        container_header = {"Accept": "{0}".format(
            image_config['mediaType'])}
        request_url = "{0}/v2/{1}{2}/blobs/{3}".format(
            self.hostname, self.base_path, image_name, image_config['digest'])
        response = self.http.request(
            "GET",
            request_url,
            headers=container_header,
            verify=not self.no_validate_ssl
        )
        if str(response.status_code)[0] == '2':
            self.last_error = None
            image_age = json.loads(response.text)
            return image_age['created']
        else:
            logging.info(" blob not found: {0}".format(self.last_error))
            self.last_error = response.status_code
            return []


def parse_args(args=None):
    parser = argparse.ArgumentParser(
        description="List or delete images from Docker registry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("""
IMPORTANT: after removing the tags, run the garbage collector
           on your registry host:

   docker-compose -f [path_to_your_docker_compose_file] run \\
       registry bin/registry garbage-collect \\
       /etc/docker/registry/config.yml

or if you are not using docker-compose:

   docker run registry:2 bin/registry garbage-collect \\
       /etc/docker/registry/config.yml

for more detail on garbage collection read here:
   https://docs.docker.com/registry/garbage-collection/
                """))
    parser.add_argument(
        '-l', '--login',
        help="Login and password for access to docker registry",
        required=False,
        metavar="USER:PASSWORD")

    parser.add_argument(
        '-w', '--read-password',
        help="Read password from stdin (and prompt if stdin is a TTY); " +
             "the final line-ending character(s) will be removed; " +
             "the :PASSWORD portion of the -l option is not required and " +
             "will be ignored",
        action='store_const',
        default=False,
        const=True)

    parser.add_argument(
        '-r', '--host',
        help="Hostname for registry server, e.g. https://example.com:5000",
        required=True,
        metavar="URL")

    parser.add_argument(
        '-p', '--path',
        help="Path to registry on the server, needed for Artifactory-based repos, "
             "e.g. 'dir' in https://example.com:5000/dir",
        required=False,
        default='')

    parser.add_argument(
        '-d', '--delete',
        help=('If specified, delete all but last {0} tags '
              'of all images').format(CONST_KEEP_LAST_VERSIONS),
        action='store_const',
        default=False,
        const=True)

    parser.add_argument(
        '-n', '--num',
        help=('Set the number of tags to keep'
              '({0} if not set)').format(CONST_KEEP_LAST_VERSIONS),
        default=CONST_KEEP_LAST_VERSIONS,
        nargs='?',
        metavar='N')

    parser.add_argument(
        '--debug',
        help=('Turn debug output'),
        action='store_const',
        default=False,
        const=True)

    parser.add_argument(
        '--dry-run',
        help=('If used in combination with --delete,'
              'then images will not be deleted'),
        action='store_const',
        default=False,
        const=True)

    parser.add_argument(
        '-i', '--image',
        help='Specify images and tags to list/delete',
        nargs='+',
        metavar="IMAGE:[TAG]")

    parser.add_argument(
        '--images-like',
        nargs='+',
        help="List of images (regexp check) that will be handled",
        required=False,
        default=[])

    parser.add_argument(
        '--keep-tags',
        nargs='+',
        help="List of tags that will be omitted from deletion if used in combination with --delete or --delete-all",
        required=False,
        default=[])

    parser.add_argument(
        '--tags-like',
        nargs='+',
        help="List of tags (regexp check) that will be handled",
        required=False,
        default=[])

    parser.add_argument(
        '--keep-tags-like',
        nargs='+',
        help="List of tags (regexp check) that will be omitted from deletion if used in combination with --delete or --delete-all",
        required=False,
        default=[])

    parser.add_argument(
        '--no-validate-ssl',
        help="Disable ssl validation",
        action='store_const',
        default=False,
        const=True)

    parser.add_argument(
        '--delete-all',
        help="Will delete all tags. Be careful with this!",
        const=True,
        default=False,
        action="store_const")

    parser.add_argument(
        '--layers',
        help=('Show layers digests for all images and all tags'),
        action='store_const',
        default=False,
        const=True)

    parser.add_argument(
        '--delete-by-hours',
        help=('Will delete all tags that are older than specified hours. Be careful!'),
        default=False,
        nargs='?',
        metavar='Hours')

    parser.add_argument(
        '--keep-by-hours',
        help=('Will keep all tags that are newer than specified hours.'),
        default=False,
        nargs='?',
        metavar='Hours')

    parser.add_argument(
        '--digest-method',
        help=('Use HEAD for standard docker registry or GET for NEXUS'),
        default='HEAD',
        metavar="HEAD|GET"
    )
    parser.add_argument(
         '--auth-method',
         help=('Use POST or GET to get JWT tokens'),
         default='POST',
         metavar="POST|GET"
    )
    return parser.parse_args(args)


def delete_tags(
        registry, image_name, dry_run, tags_to_delete, tags_to_keep):

    keep_tag_digests = {}

    if tags_to_keep:
        logging.info("Getting digests for tags to keep:")
        for tag in tags_to_keep:

            logging.debug("Getting digest for tag {0}".format(tag))
            digest = registry.get_tag_digest(image_name, tag)
            if digest is None:
                logging.info("Tag {0} does not exist for image {1}. Ignore here."
                             .format(tag, image_name))
                continue

            logging.info("Keep digest {0} for tag {1}".format(digest, tag))
            keep_tag_digests.setdefault(digest, {})
            keep_tag_digests[digest]["reason"] = "kept"
            keep_tag_digests[digest].setdefault("tags", [])
            keep_tag_digests[digest]["tags"].append(tag)

    def delete(tag):
        logging.info("  deleting tag {0}".format(tag))
        registry.delete_tag(image_name, tag, dry_run, keep_tag_digests)

    p = ThreadPool(4)
    tasks = []
    for tag in tags_to_delete:
        if tag in tags_to_keep:
            continue
        tasks.append(p.apply_async(delete, args=(tag,)))
    for task in tasks:
        task.get()
    p.close()
    p.join()

# deleting layers is disabled because
# it also deletes shared layers
##
# for layer in registry.list_tag_layers(image_name, tag):
# layer_digest = layer['digest']
# registry.delete_tag_layer(image_name, layer_digest, dry_run)


def get_tags_like(args_tags_like, tags_list):
    result = set()
    for tag_like in args_tags_like:
        logging.info("  selecting tags like: {0}".format(tag_like))
        for tag in tags_list:
            if re.search(tag_like, tag):
                logging.info("  tag {0} matches {1}".format(tag, tag_like))
                result.add(tag)
    return result


def get_tags(all_tags_list, image_name, tags_like):
    # check if there are args for special tags
    result = set()
    if tags_like:
        result = get_tags_like(tags_like, all_tags_list)
    else:
        result.update(all_tags_list)

    # get tags from image name if any
    if ":" in image_name:
        (image_name, tag_name) = image_name.split(":")
        result = set([tag_name])

    return result


def delete_tags_by_age(registry, image_name, dry_run, hours, tags_to_keep):
    image_tags = registry.list_tags(image_name)
    tags_to_delete = []
    logging.info('---------------------------------')
    for tag in image_tags:
        image_config = registry.get_tag_config(image_name, tag)

        if image_config == []:
            logging.warning("  tag {0} config not found".format(tag))
            continue

        image_age = registry.get_image_age(image_name, image_config)

        if image_age == []:
            logging.warning("  tag {0} timestamp not found".format(tag))
            continue

        # Need to parse several different date formats, rely on ciso8601 for this
        # Examples of known formats found in dockerhub/artifactory:
        #   2019-01-18T08:27:13.423155
        #   2019-01-18T08:27:13.423155Z
        #   2019-01-18T08:27:13.423156538Z
        #   1970-01-01T00:00:00Z
        parsed_image_age = ciso8601.parse_datetime(image_age)
        # Make sure the timezone is part of parsed_image_age, if not, use local timezone
        if parsed_image_age.tzinfo is None or parsed_image_age.tzinfo.utcoffset(parsed_image_age) is None:
            parsed_image_age = parsed_image_age.replace(tzinfo=dateutil.tz.tzlocal())
        # Check tag date
        if parsed_image_age < dt.now(tz=dateutil.tz.tzlocal()) - timedelta(hours=int(hours)):
            logging.info("  tag is old enough to be deleted: {0} timestamp: {1} parsed timestamp: {2}"
                         .format(tag, image_age, parsed_image_age))
            tags_to_delete.append(tag)

    logging.info('------------deleting-------------')
    delete_tags(registry, image_name, dry_run, tags_to_delete, tags_to_keep)


def get_newer_tags(registry, image_name, hours, tags_list):
    def newer(tag):
        image_config = registry.get_tag_config(image_name, tag)
        if image_config == []:
            logging.warning("  tag {0} not found".format(tag))
            return None
        image_age = registry.get_image_age(image_name, image_config)
        logging.info("Processing {0} {1}".format(tag, image_age))
        if image_age == []:
            logging.warning("  tag {0} timestamp not found".format(tag))
            return None
        # Need to parse several different date formats, rely on ciso8601 for this
        # Examples of known formats found in dockerhub/artifactory:
        #   2019-01-18T08:27:13.423155
        #   2019-01-18T08:27:13.423155Z
        #   2019-01-18T08:27:13.423156538Z
        #   1970-01-01T00:00:00Z
        parsed_image_age = ciso8601.parse_datetime(image_age)
        # Make sure the timezone is part of parsed_image_age, if not, use local timezone
        if parsed_image_age.tzinfo is None or parsed_image_age.tzinfo.utcoffset(parsed_image_age) is None:
            parsed_image_age = parsed_image_age.replace(tzinfo=dateutil.tz.tzlocal())
        # Check tag date
        if parsed_image_age >= dt.now(tz=dateutil.tz.tzlocal()) - timedelta(hours=int(hours)):
            logging.info("  tag is new enough to be kept: {0} timestamp: {1} parsed timestamp: {2}"
                         .format(tag, image_age, parsed_image_age))
            return tag
        else:
            logging.info("  tag is old enough to be deleted: {0} timestamp: {1} parsed timestamp: {2}"
                         .format(tag, image_age, parsed_image_age))
            return None

    logging.info('---------------------------------')
    p = ThreadPool(4)
    result = list(x for x in p.map(newer, tags_list) if x)
    p.close()
    p.join()
    return result


def keep_images_like(image_list, regexp_list):
    if image_list is None or regexp_list is None:
        return []
    result = []
    regexp_list = list(map(re.compile, regexp_list))
    for image in image_list:
        for regexp in regexp_list:
            if re.search(regexp, image):
                result.append(image)
                break
    return result


def main_loop(args):

    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(format='%(asctime)s %(levelname)-10s %(message)s',
                        datefmt='%d-%b-%y %H:%M:%S',
                        level=log_level)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    keep_last_versions = int(args.num)

    if args.no_validate_ssl:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    if args.read_password:
        if args.login is None:
            logging.error("Please provide -l when using -w")
            sys.exit(1)

        if ':' in args.login:
            (username, password) = args.login.split(':', 1)
        else:
            username = args.login

        if sys.stdin.isatty():
            # likely interactive usage
            password = getpass()

        else:
            # allow password to be piped or redirected in
            password = sys.stdin.read()

            if len(password) == 0:
                logging.error("Password was not provided")
                sys.exit(1)

            if password[-(len(os.linesep)):] == os.linesep:
                password = password[0:-(len(os.linesep))]

        args.login = username + ':' + password

    registry = Registry.create(args.host, args.login, args.no_validate_ssl,
                               args.path, args.digest_method)
    registry.init_auth_schemes()

    if args.delete:
        logging.info("---------------------------------")
        logging.info("Will keep last {0} tags for all images".format(keep_last_versions))

    if args.image is not None:
        image_list = args.image
    else:
        image_list = registry.list_images()
        if args.images_like:
            image_list = keep_images_like(image_list, args.images_like)

    # loop through registry's images
    # or through the ones given in command line
    for image_name in image_list:
        logging.info("---------------------------------")
        logging.info("Image: {0}".format(image_name))

        all_tags_list = registry.list_tags(image_name)

        if not all_tags_list:
            logging.info("  no tags!")
            continue

        tags_list = get_tags(all_tags_list, image_name, args.tags_like)

        # print(tags and optionally layers
        for tag in tags_list:
            logging.info("  tag: {0}".format(tag))
            if args.layers:
                for layer in registry.list_tag_layers(image_name, tag):
                    if 'size' in layer:
                        logging.info("    layer: {0}, size: {1}"
                                     .format(layer['digest'], layer['size']))
                    else:
                        logging.info("    layer: {0}"
                                     .format(layer['blobSum']))

        # add tags to "tags_to_keep" list, if we have regexp "tags_to_keep"
        # entries or a number of hours for "keep_by_hours":
        keep_tags = []
        if args.keep_tags_like:
            keep_tags.extend(get_tags_like(args.keep_tags_like, tags_list))
        if args.keep_by_hours:
            keep_tags.extend(get_newer_tags(registry, image_name,
                                            args.keep_by_hours, tags_list))
        keep_tags = list(set(keep_tags))  # Eliminate duplicates

        # delete tags if told so
        if args.delete or args.delete_all:
            if args.delete_all:
                tags_list_to_delete = list(tags_list)
            else:
                tags_list_to_delete = sorted(tags_list, key=natural_keys)[
                    :-keep_last_versions]

                # A manifest might be shared between different tags. Explicitly add those
                # tags that we want to preserve to the keep_tags list, to prevent
                # any manifest they are using from being deleted.
                tags_list_to_keep = [
                    tag for tag in tags_list if tag not in tags_list_to_delete]
                keep_tags.extend(tags_list_to_keep)
            keep_tags = list(set(keep_tags))  # Eliminate duplicates
            logging.info("  Will keep tags:")
            logging.info("\n" + pprint.pformat(keep_tags))
            delete_tags(
                registry, image_name, args.dry_run,
                tags_list_to_delete, keep_tags)

        # delete tags by age in hours
        if args.delete_by_hours:
            keep_tags.extend(args.keep_tags)
            keep_tags = list(set(keep_tags))  # Eliminate duplicates
            logging.info("  Will keep tags:")
            logging.info("\n" + pprint.pformat(keep_tags))
            delete_tags_by_age(registry, image_name, args.dry_run,
                               args.delete_by_hours, keep_tags)

if __name__ == "__main__":
    args = parse_args()
    try:
        main_loop(args)
    except KeyboardInterrupt:
        logging.info("Ctrl-C pressed, quitting")
        sys.exit(1)
