import redis
import matplotlib.pyplot as plt

clean_counts = {}
clean_connection = redis.Redis(host='localhost', db=0)
instructions = clean_connection.keys()
for inst in instructions:
	clean_counts[inst] = int(clean_connection.get(inst))
clean_total = clean_counts['total']
del clean_counts['total']
clean_sorted_counts = sorted(clean_counts.items(),key=lambda x: x[1])
for i in range(1,11):
	inst = clean_sorted_counts[len(clean_sorted_counts)-i]
	percentage = (float(inst[1]) / clean_total) * 100
	print str(i) + " : " + inst[0] + ", " + str(percentage) + "%" 
print "Total number of clean instructions: " + str(clean_total)

mal_counts = {}
mal_connection = redis.Redis(host='localhost', db=1)
instructions = mal_connection.keys()
for inst in instructions:
	mal_counts[inst] = int(mal_connection.get(inst))
mal_total = mal_counts['total']
del mal_counts['total']
mal_sorted_counts = sorted(mal_counts.items(),key=lambda x: x[1])
for i in range(1,11):
	inst = mal_sorted_counts[len(mal_sorted_counts)-i]
	percentage = (float(inst[1]) / mal_total) * 100
	print str(i) + " : " + inst[0] + ", " + str(percentage) + "%" 
print "Total number of malicious instructions: " + str(mal_total)

clean_labels = [x[0] for x in clean_sorted_counts]
clean_values = [float(x[1]) / clean_total for x in clean_sorted_counts]

mal_labels = [x[0] for x in mal_sorted_counts]
mal_values = [float(x[1]) / mal_total for x in mal_sorted_counts]

fig = plt.figure(figsize=(20,10))
p1 = fig.add_subplot(1,2,1)
p1.pie(clean_values, labels=clean_labels)
p1.set_title('clean')
p2 = fig.add_subplot(1,2,2)
p2.pie(mal_values, labels=mal_labels)
p2.set_title('malicious')
plt.savefig('pie_charts.png')