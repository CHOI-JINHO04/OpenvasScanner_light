###################
#   /usr/bin/bash
#   made by jackson
#   using > python hash_check.py [filename.xlsx]
###################


import requests
import time
import csv,sys
from openpyxl import Workbook
import queue

q = queue.Queue()
container=[]
matrix = []
de_metrix=[]
result_check_hash = []
check_malwares = []
readfile = "hash.csv"
strr = ""

APIs = [
	"input ",
	"api key"
    ]
url = "https://www.virustotal.com/vtapi/v2/file/report"
compared_sha1_index = {}
output_sheet_name = "hash_check"
output_file = sys.argv[1]
wb = Workbook()
ws = wb.active
ws.title = output_sheet_name
MinPerSeconds = 60

def select_vtkey():
	global APIs
	for i in APIs:
		q.put(i)

def hash_de_duplication():
	with open(readfile,'r') as csvreadfile:
		readcsv = csv.reader(csvreadfile)
		for row in readcsv: 
			if len(matrix) == 0:
				matrix.append(row)
			elif len(matrix) > 0:
				matrix.append(row)
				container.append(row[0])
	set_matrix = list(set(container))
	return (set_matrix)

def search_hash_value(sha1):
	vtkey = q.get()
	parameter = {"resource": sha1 , "apikey":vtkey}
	q.put(vtkey)
	
	try:
		while True:
			time.sleep(MinPerSeconds/(len(APIs)*4))
			req = requests.get(url, parameter)
			if req.status_code == "":
				print("i don't have response")
				pass
			elif req.status_code == 200:
				json = req.text
				return json
				break
			elif req.status_code == 204:
				print ("too fast just seconds")
				pass
			elif req.status_code == 400:
				print ("bad requests")
				pass
			elif req.status_code == 403:
				print("check your api key")
	except BaseException as e:
		print (e)
		
def check_result_hash(json):
			if '"response_code": 0' in json:
				return "No Matches"
			else:
				if '"detected": true' in json:
					return "Malwares"
				else:
					return "Clean"

def check_hash_save_result(de_metrix):
	global compared_sha1_index
	sha1 = []
	sha1 = de_metrix
	for i in range(0,len(sha1)):
		json = search_hash_value(sha1[i])
		result = check_result_hash(json)
		compared_sha1_index[sha1[i]] = result

def compared_hash_input_csv():
	global compared_sha1_index
	with open(readfile,'r') as csvreadfile:
		readcsv = csv.reader(csvreadfile)
		for row in readcsv:
			check_malwares.append(row)
			sha1 = row[0]
			if len(check_malwares) == 1:
				row[4] = "VT_RESULT"
				ws.append([row[0],row[1],row[2],row[3],row[4]])
			elif len(check_malwares) > 1:
				for key in compared_sha1_index.keys():
					if row[0] == key:
						row[4] = compared_sha1_index.get(key)
				ws.append([row[0],row[1],row[2],row[3],row[4]])

	count_malwares = check_malwares.count('Malwares')
	print('malwares count : ', count_malwares)
	wb.save(output_file)
	csvreadfile.close()

if __name__== "__main__":
	startTime = time.time() 
	print(time.time() - startTime)
	select_vtkey()
	de_metrix = hash_de_duplication()
	check_hash_save_result(de_metrix)
	compared_hash_input_csv()
	compared_sha1_index.clear()
	print(time.time() - startTime)
	
