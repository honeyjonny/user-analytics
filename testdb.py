# encoding: UTF-8

import asyncio
import aiopg
from datetime import datetime
from ipaddress import IPv4Address

CREATE_IPTABLE = """CREATE TABLE IF NOT EXISTS iptable( 
        	user_id int,
        	ip_addres inet,
        	date timestamp,
        	CONSTRAINT user_and_ip UNIQUE(user_id, ip_addres) );"""

INSERT_VALUES = """INSERT INTO iptable VALUES ( %d, '%s', '%s');"""

USER_NET_COMBS_FUNC = """create or replace function user_net_combs(int) 
returns table(firstip inet, secip inet) as $$ 
select distinct t1.ip_addres, t2.ip_addres 
from iptable as t1, iptable as t2 
where (t1.user_id = $1 and t2.user_id = $1) and (t1.ip_addres < t2.ip_addres) 
$$ 
language sql;"""       	


USERS_ANALYSIS_TABLE = """create table if not exists corellation(
first_user int,
second_user int,
number_nets int default 0,
constraint uniq_usrers_pair unique(first_user, second_user) );"""

async def connectdb(dsn):
	return await aiopg.create_pool(dsn)


async def create_iptable(conn_pool):    
    with await conn_pool.cursor() as cur:
        await cur.execute(CREATE_IPTABLE)


async def setup_analysis(conn_pool):
    with await conn_pool.cursor() as cur:
        await cur.execute(USER_NET_COMBS_FUNC)
        await cur.execute(USERS_ANALYSIS_TABLE)


async def populatedb(conn_pool):

	values = [
		#uid, ip
		(1, "10.10.2.4"),
		(1, "10.10.3.6"),
		(1, "10.10.8.7"),
		(1, "10.10.9.5"),

		(2, "10.10.2.4"),
		(2, "10.10.3.6"),
		(2, "10.10.8.7"),
		(2, "10.10.9.6"),
		
		(3, "10.10.8.7"),
		(3, "10.10.9.6"),
		(3, "10.10.7.7"),
		(3, "10.10.4.5"),

	]

	with await conn_pool.cursor() as cur:
		for value in values:
			uid, ip = value
			await cur.execute( INSERT_VALUES % (uid, ip, datetime.now()))

		print("done")


async def get_subnet_diffs(cur, user):
	sql = "select * from user_net_combs(%d)" % user
	# """select distinct t1.ip_addres, t2.ip_addres 
	# from iptable as t1, iptable as t2 
	# where (t1.user_id = %d and t2.user_id = %d) and (t1.ip_addres < t2.ip_addres);""" % (user, user)

	def is_diff_subnets(ip_pair):
		#print(ip_pair)
		first_ip, sec_ip = ip_pair

		first_ip = int(IPv4Address(first_ip))
		sec_ip = int(IPv4Address(sec_ip))

		first_ip = first_ip >> 8
		sec_ip = sec_ip >> 8

		result = first_ip ^ sec_ip

		res = result != 0
		#print(res)
		return res

	await cur.execute(sql)
		# for x in cur:
		# 	print(x)
	filtered = filter(is_diff_subnets, cur)
	return filtered
		# for net in filtered:
		# 	print(net)


async def analys_users(conn_pool, user_one, user_two):
	# with await conn_pool.cursor() as cur:
	# 	await cur.execute("SELECT DISTINCT ip_addres FROM iptable WHERE user_id IN ( %d, %d );" % (user_one, user_two))

	# 	for row in cur:
	# 		print(row)

	set_one = set()
	set_two = set()

	with await conn_pool.cursor() as cur:
		subnets_one = await get_subnet_diffs(cur, user_one)
		set_one = set(subnets_one)

	with await conn_pool.cursor() as cur:
		subnets_two = await get_subnet_diffs(cur, user_two)	
		set_two = set(subnets_two)

	common_subs = set_one & set_two

	print(set_one)
	print(set_two)
	print(common_subs)

	common_nets = len(common_subs)

	if common_nets >= 2:
		sql = "insert into corellation values(%d, %d, %d);" % (user_one, user_two, common_nets)
		with await conn_pool.cursor() as curs:
			await curs.execute(sql)
			print(curs.statusmessage)

		print(sql)


async def main():
	dsn = "dbname=analysis user=testuser password=db1June host=127.0.0.1"
	pool = await connectdb(dsn)
	#await create_iptable(pool)
	#await populatedb(pool)
	#await setup_analysis(pool)
	await analys_users(pool, 1,2)
	await analys_users(pool, 2,3)
	await analys_users(pool, 1,3)


if __name__ == '__main__':
	loop = asyncio.get_event_loop()
	loop.run_until_complete(main())