
tbl=[]
mac_list=[]
with open("/users/jimgiordan/kh.txt", "r") as data:
	lines = data.readlines()

for line in lines:
	parts = line.split()
	if str(parts[2]) in mac_list:
		pass
	else:
		mac_list.append(str(parts[2]))
		
print(len(lines), len(mac_list))
mac_list.sort()
print(mac_list)
