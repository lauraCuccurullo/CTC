class LogicalPlanner:

    def __init__(self, operation, planning_svc):
        self.operation = operation
        self.planning_svc = planning_svc
        self.agent_svc = planning_svc.get_service('agent_svc')
        self.data_svc = planning_svc.get_service('data_svc')

    async def execute(self, phase):
        host1_guid_list = ['c927fd39-7dd4-457a-a21b-918b0abc8c99', '2f1843dd-cca9-4b7c-a8c7-d860839db912','ceb4d01f-e650-43be-83c4-7e95ef86bc95','f3f6df4d-37cd-43e6-bb2a-693e84e255c6','ae99b403-6e62-4025-9195-3f770b15ad69']
        host1_action_list = []

        operation = (await self.data_svc.explode('operation', dict(id=self.operation['id'])))[0]

        for ps in operation['adversary']['phases'].keys():
            for a in operation['adversary']['phases'][ps]:
                if a['ability_id'] in host1_guid_list:
                    host1_action_list.append(a['id'])

        for member in operation['host_group']:
            for l in await self.planning_svc.select_links(operation, member, phase):
                if l['ability'] in host1_action_list and l['paw']=='laura$laura':
                    await self.agent_svc.perform_action(l)
                elif l['ability'] not in host1_action_list and l['paw']=='www$helpdesk':
                    await self.agent_svc.perform_action(l)
