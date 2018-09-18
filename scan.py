#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    weakfilescan

    :author:    thinker-share
    :homepage:  https://github.com/thinker-share
"""

import os
import re
import sys
import json
import Queue
import optparse
import threading

from getlink import *
from config import *
from common import http_request_get

reload(sys) 
sys.setdefaultencoding("utf-8")

def save_data(filename, data):
	fd = open(filename, 'w')
	json.dump(data, fd, indent=4, ensure_ascii=False)
	fd.close()

def get_fuzz_url(alllinks, basedomain):
	save_data('report/' + basedomain + '/link.json', alllinks)

	links = []
	for category in alllinks.keys():
		if category == 'a':
			for first_level_url in alllinks[category].keys():
				for second_level_url in alllinks[category][first_level_url].keys():
					if '://' not in second_level_url:
						continue
					domain = second_level_url.split('/')[2]
					if domain == basedomain and second_level_url not in links:
						#print '    add link:' + second_level_url
						links.append(second_level_url)
				
					for third_level_url in alllinks[category][first_level_url][second_level_url]:
						if '://' not in third_level_url:
							continue
						domain = third_level_url.split('/')[2]
						if domain == basedomain and third_level_url not in links:
							#print '    add link:' + third_level_url
							links.append(third_level_url)
		else:
			for first_level_url in alllinks[category].keys():
				for second_level_url in alllinks[category][first_level_url]:
					if '://' not in second_level_url:
						continue
					domain = second_level_url.split('/')[2]
					if domain == basedomain and second_level_url not in links:
						links.append(second_level_url)
				
	
	dirs = []
	urls = []
	for i in links:
		protocol = i.split(basedomain)[0].lstrip()
		path = i.split(basedomain)[1]
		p = path.split('/')
		length = len(p)
	
		if protocol[:4] != 'http' or '..' in path:
			continue

		url0 = protocol + basedomain + '/'
		if url0 not in dirs:
			dirs.append(url0)
			
		if fuzz_deep >= 1 and length >= 3:
			url1 = protocol + basedomain + '/' + p[1] + '/'
			if '?' not in url1 and url1 not in dirs:
				dirs.append(url1)
				for j in ['.rar','.tgz','.tar.gz','.zip','.7z']:
					if url1.rstrip('/') not in urls:
						urls.append(url1.rstrip('/') + j)
		
		if fuzz_deep >= 2 and length >= 4:
			url2 = protocol + basedomain + '/' + p[1] + '/' + p[2] + '/'
			if '?' not in url2 and url2 not in dirs:
				dirs.append(url2)
				for j in ['.rar','.tgz','.tar.gz','.zip','.7z']:
					if url2.rstrip('/') not in urls:
						urls.append(url2.rstrip('/') + j)
		
	dirs.sort()
	save_data('report/' + basedomain + '/dirs', dirs)

	f = open(dict_file, 'r')
	items = f.readlines()
	f.close()
	for j in dirs:
		for i in items:
			if '#' in i or '/' not in i:
				continue
			urls.append(j.rstrip('/') + i.rstrip())
	print '#' * 50 + 'find total ' + str(len(dirs)) + ' dirs' + '#' * 50
	print '#' * 50 + 'gene total ' + str(len(urls)) + ' urls' + '#' * 50

	return urls


def start_fuzz(urls):
	queue = Queue.Queue()
	for url in urls:
		queue.put(url)

	threads = []
	for i in xrange(threads_count):
		threads.append(bruteWorker(queue))

	for t in threads: t.start()
	for t in threads: t.join()
		
	
class bruteWorker(threading.Thread):
	def __init__(self, queue):
		threading.Thread.__init__(self)
		self.queue = queue
		self.count = 0

	def run(self):
		try:
			while not self.queue.empty():
				sub = self.queue.get_nowait()
				ret = http_request_get(sub)	
				if ret.status_code in exclude_status and not re.findall(not_find_reg, ret.text):
					print sub
					self.count += 1
					if self.count >= result_cnt:
						print '可能误报，请手动检查!'
						break
		except Exception, e:
			pass


def do_work(url):
	alllinks, basedomain = GetAllLink(url).start()
	urls = get_fuzz_url(alllinks, basedomain)
	start_fuzz(urls)


def init_opt():
	parser = optparse.OptionParser('usage: ./%prog [options] \n'
									'Example:\n' 
									'		./scan.py -f rule.json')
	parser.add_option('-u', '--url', dest='url', default='', type='string', help='the entry url.')
	(options, args) = parser.parse_args()
	
	if options.url == '':
		print 'no url, exit.'
		sys.exit(1)

	os.system('mkdir -p report')
	os.system("rm -rf report/" + options.url.split('/')[2])
	os.system("mkdir report/" + options.url.split('/')[2])
	return options.url

if __name__ == '__main__':
	url = init_opt()
	do_work(url)
