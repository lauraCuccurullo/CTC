from plugins.stockpile.app.parsers.base_parser import BaseParser
from plugins.stockpile.app.relationship import Relationship


class Parser(BaseParser):

    def __init__(self, parser_info):
        self.mappers = parser_info['mappers']
        self.used_facts = parser_info['used_facts']

    def parse(self, blob):
        relationships = []
        for match in self.line(blob):            
            if "password:" not in match:
                continue
            match=match.split("login: ")
            match=match[1].split("   password: ") 
            print(match[0])
            print(match[1])

            for mp in self.mappers:
                source = self.set_value(mp.get('source'), match[0], self.used_facts)
                target = self.set_value(mp.get('target'), match[1], self.used_facts)
                relationships.append(
                    Relationship(source=(mp.get('source'), source),
                                 edge=mp.get('edge'),
                                 target=(mp.get('target'), target))
                )
        return relationships
