import os

class LogicalPlanner:
   
    def __init__(self, operation, planning_svc):
        self.operation = operation
        self.planning_svc = planning_svc
        self.agent_svc = planning_svc.get_service('agent_svc')
        self.data_svc = planning_svc.get_service('data_svc')
        self.correct_executed = []


    async def execute(self, phase):
        crack_path="../CrackToCaldera/"
        path_planner=crack_path+"new_plan.txt"
        reachable_file_name=crack_path+"reachable_host.txt"
        host_tech_dict = {}
        host_action_dict = dict()
        host_reachable = []

        #get foreach action in the plan the correct technique
        with open(path_planner, 'r') as read_plan:
            for line in read_plan:
                line=line.replace("\n","")
                line=line.replace(" ","")
                line = line.split(",")
                host_tech_dict[line[1]] = line[2]

        with open(reachable_file_name, 'r') as reachable_hosts:
            for line in reachable_hosts:
                line=line.replace("\n","")
                line=line.replace(" ","")
                line = line.split(",")
                host_reachable.append([line[0], line[1]])

        operation = (await self.data_svc.explode('operation', dict(id=self.operation['id'])))[0]

        for ps in operation['adversary']['phases'].keys():
            for a in operation['adversary']['phases'][ps]:
                #add foreach technique in the plan the correct host
                if host_tech_dict.get(a['ability_id']):
                    if a['id'] in host_action_dict:
                        new_host=host_tech_dict.get(a['ability_id'])
                        if new_host not in host_action_dict.get(a['id']):
                            host_action_dict[a['id']].append(new_host)
                            print('host_action_dict')                        
                    else:
                        host_action_dict[a['id']]=host_tech_dict.get(a['ability_id'])

        existent_agents=[]
        for member in operation['host_group']:
            for l in await self.planning_svc.select_links(operation, member, phase):
                if l['paw'] not in existent_agents:
                    existent_agents.append(l['paw'])

        for member in operation['host_group']:
            #print("phase: "+str(phase))
            #print(await self.planning_svc.select_links(operation, member, phase))
            #print("--prec")
            #print(await self.planning_svc.select_links(operation, member, (phase-1)))
            for l in await self.planning_svc.select_links(operation, member, phase):
                #print("----")

                #if an agent is specified
                if host_action_dict.get(l['ability']):
                    correct_host=host_action_dict.get(l['ability'])

                    #if specified agent exist
                    if correct_host in existent_agents:
                        if l['paw']==correct_host:
                            print('SPECIFIED AND EXIST '+ l['paw'] + " " +correct_host + " " + str(l['ability']))
                            self.correct_executed.append([l['ability'], l['paw']])
                            await self.agent_svc.perform_action(l)
                            print('after '+str(phase))
                    else:
                        if [l['ability'], correct_host] not in self.correct_executed:
                            found=False
                            for host in host_reachable:
                                if host[1]==correct_host:
                                    if host[0]==l['paw']:
                                        print('SPECIFIED BUT NOT EXIST '+ l['paw'] + " " +correct_host + " " + str(l['ability']))
                                        await self.agent_svc.perform_action(l)
                                        print('after '+str(phase))
                                        found=True
                                if found:
                                    break
                else:
                    print("NOT SPECIFIED "+ l['paw'] + " " + str(l['ability']))
                    await self.agent_svc.perform_action(l)
                    print('after '+str(phase))
