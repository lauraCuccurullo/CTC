import os
import json
import re
import yaml
import uuid

user_list = []
host_list = ["client_1"]
reachable_host_list = []
principal_list = ["eve_1"]
attacks_list=[]

def hasUser(p):
    default_t= []
    id=p[1]
    username=p[2]
    host=p[3]
    password=p[4]
    role=p[5]
    if username in user_list: 
        return "hasUser", id, default_t, host,username,password,role
    return
    
def hasAccount(p):
    default_t= []
    id=p[1]
    principal=p[2]
    host=p[3]
    username=p[4]
    if principal in principal_list: 
        if host not in host_list:
            host_list.append(host)
        if username not in user_list:
            user_list.append(username)
        return "hasAccount ",id, default_t, host,username,principal
    return

def knows(p):
    default_t= []
    id=p[1]
    principal=p[2]
    datum=p[3]
    return "knows",id, default_t, "",principal,datum

def listeningOn(p):
    default_t= []
    id=p[1]
    host=p[2]
    protocol=p[3]
    port=p[4]
    if host in host_list:
        return "listeningOn",id, default_t, host,protocol,port

def isConnected(p):
    default_t= []
    id=p[1]
    host=p[2]
    address=p[3]
    if host in host_list:
        return "isConnected",id, default_t, host,address

def hostACL(p):
    default_t= ["nmap"]
    id=p[1]
    srchost=p[2]
    dsthost=p[3]
    protocol=p[4]
    port=p[5]
    if srchost in host_list:
        reachable_host_list.append([srchost, dsthost])
        return "hostACL", id, default_t, srchost,dsthost,protocol,port
    return 

def existsRoute(p):
    default_t= []
    id=p[1]
    srchost=p[2]
    dsthost=p[3]
    host=p[4]
    if srchost in host_list:
        return "existsRoute",id, default_t, srchost,dsthost,host

def isRouter(p):
    default_t= []
    id=p[1]
    host=p[2]
    if host in host_list:
        return "isRouter",id, default_t, host

def get_predicate(p, a):
    switcher={
        'knows':knows,
        'hasAccount':hasAccount,
        'hasUser': hasUser,
        'listeningOn':listeningOn,
        'isConnected':isConnected,
        'hostACL':hostACL,
        }
    func = switcher.get(p, lambda a :'Invalid predicate')
    return func(a)

input_file_name="goal1.trace"
input_json_name="datalog1.json"
output_file_name="planner.txt"
reachable_file_name="reachable_host.txt"
path_table = "techniques_table.txt"
host_table = "host_association.txt"
techniques_dict = {}
host_dict = {}

#create dictionary with corrispondence between id technique and name
with open(path_table, 'r') as read_table:
    for line in read_table:
        line=line.replace("\n","")
        line = line.split(", ")
        techniques_dict[line[1]]=line[0]

#get association between name host for Crack and for Caldera
with open(host_table, 'r') as read_host_table:
    for line in read_host_table:
        line=line.replace("\n","")
        line = line.split(", ")
        host_dict[line[0]]=line[1]

for root, dirs, files in os.walk("output"):  
    
    if input_file_name not in files:
        continue
    #open json file 
    with open(os.path.join(root, input_json_name), 'r') as json_file:
        objson = json.load(json_file)
    
    keys_list = list(objson['id'].keys())
    pred_list = []

    #create adversary file and pre information
    adversary_uuid=str(uuid.uuid4())
    adversary_file_name=adversary_uuid+".yml"
    adversary_path='../caldera/plugins/stockpile/data/adversaries/A'+adversary_file_name
    write_adversary=open(adversary_path, "w+")
    write_adversary.write("description: aaa\nid: "+adversary_uuid+"\nname: aaa\nphases: \n")

    write_planner=open("new_plan.txt", "w+")

    with open(os.path.join(root, input_file_name), 'r') as read_file:
        write_file=open(output_file_name, "w+") 
        for line in read_file:
            #extract only new fact
            if ":New fact :" in line: 
                line = line.split("INFO:pyDatalog.pyEngine:New fact : ")[1]
                new_line = re.findall(r"[\w]+", line)

                #find the corresponding json obj
                if new_line[1] in keys_list:
                    pred=get_predicate(new_line[0], new_line)
                    if 'Invalid predicate'==pred:
                        continue
                    #check requirements
                    if objson['id'][new_line[1]]['requirement']!="":
                        #if req is not satisfied: continue
                        #-- to do -- 
                        print("REQUIREMENTS -------- "+line)
                
                    #write_file.writelines("%s " % p for p in pred))
                    if pred:
                        pred_list.append(pred)    
                        type_name = objson['id'][new_line[1]]['type']
                        try:
                            techniques_preparatory = objson['id'][new_line[1]]['techniques_preparatory']
                        except KeyError:
                            techniques_preparatory = []
                        try:
                            techniques_attack = objson['id'][new_line[1]]['techniques_attack']
                        except KeyError:
                            techniques_attack=pred[2]
                        
                        host_name=""
                        for elem in host_list:
                            if host_dict.get(pred[3]):
                                host_name=host_dict.get(pred[3])
                                break

                        if techniques_preparatory or techniques_attack:
                            attacks_list.append([pred[1],techniques_preparatory,techniques_attack, host_name])
                        
                        for t_prep in techniques_preparatory:
                            if techniques_dict.get(t_prep):
                                write_planner.write( pred[1]+","+ techniques_dict.get(t_prep)+", "+host_name+"\n")
                        for t_attack in techniques_attack:
                            if techniques_dict.get(t_attack):
                                write_planner.write( pred[1]+","+ techniques_dict.get(t_attack)+", "+host_name+"\n")

    #write information file
    for p in pred_list:
        p=p[0]+", ID: "+p[1]+", TECHNIQUES: "+str(p[2])+", SOURCE HOST: "+p[3]+"\n"
        write_file.write(p)    

    #write file with host reachable
    association_file=open(reachable_file_name, "w+") 
    for host in reachable_host_list:
        association_file.write(host_dict.get(host[0]) +", "+ host_dict.get(host[1])+"\n")

    #write new adversary
    i=0
    for a in attacks_list:
        if a[1]: 
            write_adversary.write("  "+str(i)+": \n")
            for t_prep in a[1]:
                if techniques_dict.get(t_prep):
                    write_adversary.write("    - "+ techniques_dict.get(t_prep)+"\n")
            i+=1
        if a[2]:
            write_adversary.write("  "+str(i)+": \n")
            for t_attack in a[2]:
                if techniques_dict.get(t_attack):
                    write_adversary.write("    - "+ techniques_dict.get(t_attack)+"\n")
            i+=1

    association_file.close()
    read_file.close()
    write_file.close()
    json_file.close()