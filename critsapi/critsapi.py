import datetime
import json
import logging
import os
import requests

from critsapi.exceptions import CRITsOperationalError
from critsapi.exceptions import CRITsInvalidTypeError
from critsapi.vocabulary import IndicatorThreatTypes as itt
from critsapi.vocabulary import IndicatorAttackTypes as iat

log = logging.getLogger()


class CRITsAPI():

    def __init__(self, api_url='', api_key='', username='', verify=True,
                 proxies={}):
        self.url = api_url
        if self.url[-1] == '/':
            self.url = self.url[:-1]
        self.api_key = api_key
        self.username = username
        self.verify = verify
        self.proxies = proxies

    def get_object(self, obj_id, obj_type):
        type_trans = self._type_translation(obj_type)
        get_url = '{}/{}/{}/'.format(self.url, type_trans, obj_id)
        params = {
            'username': self.username,
            'api_key': self.api_key,
        }
        r = requests.get(get_url, params=params, proxies=self.proxies,
                         verify=self.verify)
        if r.status_code == 200:
            return json.loads(r.text)
        else:
            print('Status code returned for query {}, '
                  'was: {}'.format(get_url, r.status_code))
        return None

    def add_indicator(self,
                      value,
                      itype,
                      source='',
                      reference='',
                      method='',
                      campaign=None,
                      confidence=None,
                      bucket_list=[],
                      ticket='',
                      add_domain=True,
                      add_relationship=True,
                      indicator_confidence='unknown',
                      indicator_impact='unknown',
                      threat_type=itt.UNKNOWN,
                      attack_type=iat.UNKNOWN,
                      description=''):
        """
        Add an indicator to CRITs

        Args:
            value: The indicator itself
            itype: The overall indicator type. See your CRITs vocabulary
            source: Source of the information
            reference: A reference where more information can be found
            method: The method for adding this indicator
            campaign: If the indicator has a campaign, add it here
            confidence: The confidence this indicator belongs to the given
                        campaign
            bucket_list: Bucket list items for this indicator
            ticket: A ticket associated with this indicator
            add_domain: If the indicator is a domain, it will automatically
                        add a domain TLO object.
            add_relationship: If add_domain is True, this will create a
                        relationship between the indicator and domain TLOs
            indicator_confidence: The confidence of the indicator
            indicator_impact: The impact of the indicator
            threat_type: The threat type of the indicator
            attack_type: the attack type of the indicator
            description: A description of this indicator
        Returns:
            JSON object for the indicator or None if it failed.
        """
        # Time to upload these indicators
        data = {
            'api_key': self.api_key,
            'username': self.username,
            'source': source,
            'reference': reference,
            'method': '',
            'campaign': campaign,
            'confidence': confidence,
            'bucket_list': ','.join(bucket_list),
            'ticket': ticket,
            'add_domain': True,
            'add_relationship': True,
            'indicator_confidence': indicator_confidence,
            'indicator_impact': indicator_impact,
            'type': itype,
            'threat_type': threat_type,
            'attack_type': attack_type,
            'value': value,
            'description': description,
            }

        r = requests.post("{0}/indicators/".format(self.url), data=data,
                          verify=self.verify, proxies=self.proxies)
        if r.status_code == 200:
            log.debug("Indicator uploaded successfully - {}".format(value))
            ind = json.loads(r.text)
            return ind

        return None

    def add_event(self,
                  source,
                  reference,
                  event_title,
                  event_type,
                  method='',
                  description='',
                  bucket_list=[],
                  campaign='',
                  confidence='',
                  date=None):
        """
        Adds an event. If the event name already exists, it will return that
        event instead.

        Args:
            source: Source of the information
            reference: A reference where more information can be found
            event_title: The title of the event
            event_type: The type of event. See your CRITs vocabulary.
            method: The method for obtaining the event.
            description: A text description of the event.
            bucket_list: A list of bucket list items to add
            campaign: An associated campaign
            confidence: The campaign confidence
            date: A datetime.datetime object of when the event occurred.
        Returns:
            A JSON event object or None if there was an error.
        """
        # Check to see if the event already exists
        events = self.get_events(event_title)
        if events is not None:
            if events['meta']['total_count'] == 1:
                return events['objects'][0]
            if events['meta']['total_count'] > 1:
                log.error('Multiple events found while trying to add the event'
                          ': {}'.format(event_title))
                return None
        # Now we can create the event
        data = {
            'api_key': self.api_key,
            'username': self.username,
            'source': source,
            'reference': reference,
            'method': method,
            'campaign': campaign,
            'confidence': confidence,
            'description': description,
            'event_type': event_type,
            'date': date,
            'title': event_title,
            'bucket_list': ','.join(bucket_list),
        }

        r = requests.post('{}/events/'.format(self.url), data=data,
                          verify=self.verify, proxies=self.proxies)
        if r.status_code == 200:
            log.debug('Event created: {}'.format(event_title))
            json_obj = json.loads(r.text)
            if 'id' not in json_obj:
                log.error('Error adding event. id not returned.')
                return None
            return json_obj
        else:
            log.error('Event creation failed with status code: '
                      '{}'.format(r.status_code))
            return None

    def add_sample_file(self,
                        sample_path,
                        source,
                        reference,
                        method='',
                        file_format='raw',
                        file_password='',
                        sample_name='',
                        campaign='',
                        confidence='',
                        description='',
                        bucket_list=[]):
        """
        Adds a file sample. For meta data only use add_sample_meta.

        Args:
            sample_path: The path on disk of the sample to upload
            source: Source of the information
            reference: A reference where more information can be found
            method: The method for obtaining the sample.
            file_format: Must be raw, zip, or rar.
            file_password: The password of a zip or rar archived sample
            sample_name: Specify a filename for the sample rather than using
                the name on disk
            campaign: An associated campaign
            confidence: The campaign confidence
            description: A text description of the sample
            bucket_list: A list of bucket list items to add
        Returns:
            A JSON sample object or None if there was an error.
        """
        if os.path.isfile(sample_path):
            data = {
                'api_key': self.api_key,
                'username': self.username,
                'source': source,
                'reference': reference,
                'method': method,
                'filetype': file_format,
                'upload_type': 'file',
                'campaign': campaign,
                'confidence': confidence,
                'description': description,
                'bucket_list': ','.join(bucket_list),
            }
            if sample_name != '':
                data['filename'] = sample_name
            with open(sample_path, 'rb') as fdata:
                if file_password:
                    data['password'] = file_password
                r = requests.post('{0}/samples/'.format(self.url),
                                  data=data,
                                  files={'filedata': fdata},
                                  verify=self.verify,
                                  proxies=self.proxies)
                if r.status_code == 200:
                    result_data = json.loads(r.text)
                    return result_data
                else:
                    log.error('Error with status code {0} and message '
                              '{1}'.format(r.status_code, r.text))
            return None

    def add_sample_meta(self,
                        source,
                        reference,
                        method='',
                        filename='',
                        md5='',
                        sha1='',
                        sha256='',
                        size='',
                        mimetype='',
                        campaign='',
                        confidence='',
                        description='',
                        bucket_list=[]):
        """
        Adds a metadata sample. To add an actual file, use add_sample_file.

        Args:
            source: Source of the information
            reference: A reference where more information can be found
            method: The method for obtaining the sample.
            filename: The name of the file.
            md5: An MD5 hash of the file.
            sha1: SHA1 hash of the file.
            sha256: SHA256 hash of the file.
            size: size of the file.
            mimetype: The mimetype of the file.
            campaign: An associated campaign
            confidence: The campaign confidence
            bucket_list: A list of bucket list items to add
            upload_type: Either 'file' or 'meta'
        Returns:
            A JSON sample object or None if there was an error.
        """
        data = {
            'api_key': self.api_key,
            'username': self.username,
            'source': source,
            'reference': reference,
            'method': method,
            'filename': filename,
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
            'size': size,
            'mimetype': mimetype,
            'upload_type': 'meta',
            'campaign': campaign,
            'confidence': confidence,
            'bucket_list': ','.join(bucket_list),
        }
        r = requests.post('{0}/samples/'.format(self.url),
                          data=data,
                          verify=self.verify,
                          proxies=self.proxies)
        if r.status_code == 200:
            result_data = json.loads(r.text)
            return result_data
        else:
            log.error('Error with status code {0} and message '
                      '{1}'.format(r.status_code, r.text))
        return None

    def add_email(self,
                  email_path,
                  source,
                  reference,
                  method='',
                  upload_type='raw',
                  campaign='',
                  confidence='',
                  description='',
                  bucket_list=[],
                  password=''):
        """
        Add an email object to CRITs. Only RAW, MSG, and EML are supported
        currently.

        Args:
            email_path: The path on disk of the email.
            source: Source of the information
            reference: A reference where more information can be found
            method: The method for obtaining the email.
            upload_type: 'raw', 'eml', or 'msg'
            campaign: An associated campaign
            confidence: The campaign confidence
            description: A description of the email
            bucket_list: A list of bucket list items to add
            password: A password for a 'msg' type.
        Returns:
            A JSON email object from CRITs or None if there was an error.
        """
        if not os.path.isfile(email_path):
            log.error('{} is not a file'.format(email_path))
            return None
        with open(email_path, 'rb') as fdata:
            data = {
                'api_key': self.api_key,
                'username': self.username,
                'source': source,
                'reference': reference,
                'method': method,
                'upload_type': upload_type,
                'campaign': campaign,
                'confidence': confidence,
                'bucket_list': bucket_list,
                'description': description,
            }
            if password:
                data['password'] = password
            r = requests.post("{0}/emails/".format(self.url),
                              data=data,
                              files={'filedata': fdata},
                              verify=self.verify,
                              proxies=self.proxies)
            if r.status_code == 200:
                result_data = json.loads(r.text)
                return result_data
            else:
                print('Error with status code {0} and message '
                      '{1}'.format(r.status_code, r.text))
        return None

    def add_backdoor(self,
                     backdoor_name,
                     source,
                     reference,
                     method='',
                     aliases=[],
                     version='',
                     campaign='',
                     confidence='',
                     description='',
                     bucket_list=[]):
        """
        Add a backdoor object to CRITs.

        Args:
            backdoor_name: The primary name of the backdoor
            source: Source of the information
            reference: A reference where more information can be found
            method: The method for obtaining the backdoor information.
            aliases: List of aliases for the backdoor.
            version: Version
            campaign: An associated campaign
            confidence: The campaign confidence
            description: A description of the email
            bucket_list: A list of bucket list items to add
        """
        data = {
            'api_key': self.api_key,
            'username': self.username,
            'source': source,
            'reference': reference,
            'method': method,
            'name': backdoor_name,
            'aliases': ','.join(aliases),
            'version': version,
            'campaign': campaign,
            'confidence': confidence,
            'bucket_list': bucket_list,
            'description': description,
        }
        r = requests.post('{0}/backdoors/'.format(self.url),
                          data=data,
                          verify=self.verify,
                          proxies=self.proxies)
        if r.status_code == 200:
            result_data = json.loads(r.text)
            return result_data
        else:
            log.error('Error with status code {0} and message '
                      '{1}'.format(r.status_code, r.text))
        return None

    def add_profile_point(self,
                          value,
                          source='',
                          reference='',
                          method='',
                          ticket='',
                          campaign=None,
                          confidence=None,
                          bucket_list=[]):
        """
        Add an indicator to CRITs

        Args:
            value: The profile point itself
            source: Source of the information
            reference: A reference where more information can be found
            method: The method for adding this indicator
            campaign: If the indicator has a campaign, add it here
            confidence: The confidence this indicator belongs to the given
                        campaign
            bucket_list: Bucket list items for this indicator
            ticket: A ticket associated with this indicator
        Returns:
            JSON object for the indicator or None if it failed.
        """
        # Time to upload these indicators
        data = {
            'api_key': self.api_key,
            'username': self.username,
            'source': source,
            'reference': reference,
            'method': '',
            'campaign': campaign,
            'confidence': confidence,
            'bucket_list': ','.join(bucket_list),
            'ticket': ticket,
            'value': value,
            }

        r = requests.post("{0}/profile_points/".format(self.url), data=data,
                          verify=self.verify, proxies=self.proxies)
        if r.status_code == 200:
            log.debug("Profile Point uploaded successfully - {}".format(value))
            pp = json.loads(r.text)
            return pp

        return None

    def get_events(self, event_title, regex=False):
        """
        Search for events with the provided title

        Args:
            event_title: The title of the event
        Returns:
            An event JSON object returned from the server with the following:
                {
                    "meta":{
                        "limit": 20, "next": null, "offset": 0,
                        "previous": null, "total_count": 3
                    },
                    "objects": [{}, {}, etc]
                }
            or None if an error occurred.
        """
        regex_val = 0
        if regex:
            regex_val = 1
        r = requests.get('{0}/events/?api_key={1}&username={2}&c-title='
                         '{3}&regex={4}'.format(self.url, self.api_key,
                                                self.username, event_title,
                                                regex_val), verify=self.verify)
        if r.status_code == 200:
            json_obj = json.loads(r.text)
            return json_obj
        else:
            log.error('Non-200 status code from get_event: '
                      '{}'.format(r.status_code))
            return None

    def get_samples(self, md5='', sha1='', sha256=''):
        """
        Searches for a sample in CRITs. Currently only hashes allowed.

        Args:
            md5: md5sum
            sha1: sha1sum
            sha256: sha256sum
        Returns:
            JSON response or None if not found
        """
        params = {'api_key': self.api_key, 'username': self.username}
        if md5:
            params['c-md5'] = md5
        if sha1:
            params['c-sha1'] = sha1
        if sha256:
            params['c-sha256'] = sha256
        r = requests.get('{0}/samples/'.format(self.url),
                         params=params,
                         verify=self.verify,
                         proxies=self.proxies)
        if r.status_code == 200:
            result_data = json.loads(r.text)
            if 'meta' in result_data:
                if 'total_count' in result_data['meta']:
                    if result_data['meta']['total_count'] > 0:
                        return result_data
        else:
            log.error('Non-200 status code: {}'.format(r.status_code))
        return None

    def get_backdoors(self, name):
        """
        Searches a backdoor given the name. Returns multiple results

        Args:
            name: The name of the backdoor. This can be an alias.
        Returns:
            Returns a JSON object contain one or more backdoor results or
            None if not found.
        """
        params = {}
        params['or'] = 1
        params['c-name'] = name
        params['c-aliases__in'] = name
        r = requests.get('{0}/backdoors/'.format(self.url),
                         params=params,
                         verify=self.verify,
                         proxies=self.proxies)
        if r.status_code == 200:
            result_data = json.loads(r.text)
            if 'meta' in result_data:
                if 'total_count' in result_data['meta']:
                    if result_data['meta']['total_count'] > 0:
                        return result_data
        else:
            log.error('Non-200 status code: {}'.format(r.status_code))
        return None

    def get_backdoor(self, name, version=''):
        """
        Searches for the backdoor based on name and version.

        Args:
            name: The name of the backdoor. This can be an alias.
            version: The version.
        Returns:
            Returns a JSON object contain one or more backdoor results or
            None if not found.
        """
        params = {}
        params['or'] = 1
        params['c-name'] = name
        params['c-aliases__in'] = name
        r = requests.get('{0}/backdoors/'.format(self.url),
                         params=params,
                         verify=self.verify,
                         proxies=self.proxies)
        if r.status_code == 200:
            result_data = json.loads(r.text)
            if 'meta' not in result_data:
                return None
            if 'total_count' not in result_data['meta']:
                return None
            if result_data['meta']['total_count'] <= 0:
                return None
            if 'objects' not in result_data:
                return None
            for backdoor in result_data['objects']:
                if 'version' in backdoor:
                    if backdoor['version'] == version:
                        return backdoor
        else:
            log.error('Non-200 status code: {}'.format(r.status_code))
        return None

    def has_relationship(self, left_id, left_type, right_id, right_type,
                         rel_type='Related To'):
        """
        Checks if the two objects are related

        Args:
            left_id: The CRITs ID of the first indicator
            left_type: The CRITs TLO type of the first indicator
            right_id: The CRITs ID of the second indicator
            right_type: The CRITs TLO type of the second indicator
            rel_type: The relationships type ("Related To", etc)
        Returns:
            True or False if the relationship exists or not.
        """
        data = self.get_object(left_id, left_type)
        if not data:
            raise CRITsOperationalError('Crits Object not found with id {}'
                                        'and type {}'.format(left_id,
                                                             left_type))
        if 'relationships' not in data:
            return False
        for relationship in data['relationships']:
            if relationship['relationship'] != rel_type:
                continue
            if relationship['value'] != right_id:
                continue
            if relationship['type'] != right_type:
                continue
            return True
        return False

    def forge_relationship(self, left_id, left_type, right_id, right_type,
                           rel_type='Related To', rel_date=None,
                           rel_confidence='high', rel_reason=''):
        """
        Forges a relationship between two TLOs.

        Args:
            left_id: The CRITs ID of the first indicator
            left_type: The CRITs TLO type of the first indicator
            right_id: The CRITs ID of the second indicator
            right_type: The CRITs TLO type of the second indicator
            rel_type: The relationships type ("Related To", etc)
            rel_date: datetime.datetime object for the date of the
                relationship. If left blank, it will be datetime.datetime.now()
            rel_confidence: The relationship confidence (high, medium, low)
            rel_reason: Reason for the relationship.
        Returns:
            True if the relationship was created. False otherwise.
        """
        if not rel_date:
            rel_date = datetime.datetime.now()
        type_trans = self._type_translation(left_type)
        submit_url = '{}/{}/{}/'.format(self.url, type_trans, left_id)

        params = {
            'api_key': self.api_key,
            'username': self.username,
            }

        data = {
            'action': 'forge_relationship',
            'right_type': right_type,
            'right_id': right_id,
            'rel_type': rel_type,
            'rel_date': rel_date,
            'rel_confidence': rel_confidence,
            'rel_reason': rel_reason
        }

        r = requests.patch(submit_url, params=params, data=data,
                           proxies=self.proxies, verify=self.verify)
        if r.status_code == 200:
            log.debug('Relationship built successfully: {0} <-> '
                      '{1}'.format(left_id, right_id))
            return True
        else:
            log.error('Error with status code {0} and message {1} between '
                      'these indicators: {2} <-> '
                      '{3}'.format(r.status_code, r.text, left_id, right_id))
            return False

    def status_update(self, crits_id, crits_type, status):
        """
        Update the status of the TLO. By default, the options are:
        - New
        - In Progress
        - Analyzed
        - Deprecated

        Args:
            crits_id: The object id of the TLO
            crits_type: The type of TLO. This must be 'Indicator', ''
            status: The status to change.
        Returns:
            True if the status was updated. False otherwise.
        Raises:
            CRITsInvalidTypeError
        """
        obj_type = self._type_translation(crits_type)
        patch_url = "{0}/{1}/{2}/".format(self.url, obj_type, crits_id)
        params = {
            'api_key': self.api_key,
            'username': self.username,
        }

        data = {
            'action': 'status_update',
            'value': status,
        }

        r = requests.patch(patch_url, params=params, data=data,
                           verify=self.verify, proxies=self.proxies)
        if r.status_code == 200:
            log.debug('Object {} set to {}'.format(crits_id, status))
            return True
        else:
            log.error('Attempted to set object id {} to '
                      'Informational, but did not receive a '
                      '200'.format(crits_id))
            log.error('Error message was: {}'.format(r.text))
        return False

    def source_add_update(self, crits_id, crits_type, source,
                          action_type='add', method='', reference='',
                          date=None):
        """
        date must be in the format "%Y-%m-%d %H:%M:%S.%f"
        """
        type_trans = self._type_translation(crits_type)
        submit_url = '{}/{}/{}/'.format(self.url, type_trans, crits_id)

        if date is None:
            date = datetime.datetime.now()
            date = datetime.datetime.strftime(date, '%Y-%m-%d %H:%M:%S.%f')

        params = {
            'api_key': self.api_key,
            'username': self.username,
            }

        data = {
            'action': 'source_add_update',
            'action_type': action_type,
            'source': source,
            'method': method,
            'reference': reference,
            'date': date
        }

        r = requests.patch(submit_url, params=params, data=json.dumps(data),
                           proxies=self.proxies, verify=self.verify)
        if r.status_code == 200:
            log.debug('Source {0} added successfully to {1} '
                      '{2}'.format(source, crits_type, crits_id))
            return True
        else:
            log.error('Error with status code {0} and message {1} for '
                      'type {2} and id {3} and source '
                      '{4}'.format(r.status_code, r.text, crits_type,
                                   crits_id, source))
            return False

    def _type_translation(self, str_type):
        """
        Internal method to translate the named CRITs TLO type to a URL
        specific string.
        """
        if str_type == 'Indicator':
            return 'indicators'
        if str_type == 'Domain':
            return 'domains'
        if str_type == 'IP':
            return 'ips'
        if str_type == 'Sample':
            return 'samples'
        if str_type == 'Event':
            return 'events'
        if str_type == 'Actor':
            return 'actors'
        if str_type == 'Email':
            return 'emails'
        if str_type == 'Backdoor':
            return 'backdoors'

        raise CRITsInvalidTypeError('Invalid object type specified: '
                                    '{}'.format(str_type))
