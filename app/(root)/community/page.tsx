import { auth } from "@/auth";
import DataRenderer from "@/components/DataRenderer";
import Pagination from "@/components/Pagination";
import GetUsers from "@/lib/actions/GetUsers";
import UserCard from "./component/UserCard";
import { DefaultFilters, UserFilters } from "@/constant/filters";
import CommonFilter from "@/components/CommonFilter";

async function page({
  searchParams,
}: {
  searchParams: Promise<{
    [key: string]: string;
  }>;
}) {
  const session = await auth();
  const { page, pageSize, search, filter } = await searchParams;

  const { success, data, message } = await GetUsers({
    page: Number(page) || 1,
    pageSize: Number(pageSize) || 10,
    search: search || "",
    filter: filter || "",
  });

  const { users = [], isNext = false } = data || {};

  return (
    <>
      <div className="flex items-center justify-between p-5">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold">All Users</h1>
          <div>
            <CommonFilter
              filters={UserFilters}
              defaultFilter={DefaultFilters.UserFilters}
            />
          </div>
        </div>
      </div>
      <DataRenderer
        success={success}
        data={users}
        errorMessage={message}
        render={(users) => {
          return (
            <div className="grid grid-cols-4 gap-4">
              {users.map((user) => (
                <UserCard
                  key={user._id.toString()}
                  id={user._id.toString()}
                  name={user?.name}
                  image={user?.image}
                />
              ))}
            </div>
          );
        }}
      />
      <Pagination isNext={isNext} page={page || 1} />
    </>
  );
}

export default page;
