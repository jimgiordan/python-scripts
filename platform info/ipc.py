import subprocess

iflist = subprocess.run(["ipconfig", "getiflist"], capture_output=True, text = True)
for ifc in iflist.stdout.split():
	if subprocess.run(["ipconfig", "getifaddr", ifc], capture_output=True, text=True).stdout:
		summary = subprocess.run(["ipconfig", "getsummary", ifc], capture_output=True, text=True).stdout
	else:
		pass

table_data={}
for line in summary.splitlines():
	line = line.strip()
	split_arg = [" = ", " : ", ": "]
	for x in split_arg:
		if x in line:
			table_data[line.split(x, 1)[0]] = line.split(x, 1)[1]
			continue
		else:
			pass

print(f"\
IP address: {table_data['yiaddr']}\n\
Router: {table_data['siaddr']}\n\
MAC Address: {table_data['chaddr']}\n\
SSID: {table_data['SSID']}\n\
Router: {table_data['Router']}\n\
{table_data['server_identifier (ip)']}\n\
{table_data['subnet_mask (ip)']}\n\
{table_data['broadcast_address (ip)']}\n\
{table_data['domain_name_server (ip_mult)']}\n\
{table_data['router (ip_mult)']}\
")

for i in range(255):
	result = subprocess.run(["ipconfig", "getoption", ifc, str(i)], capture_output=True, text=True).stdout.strip()
	if result:
		print(f"{i} - {result}")