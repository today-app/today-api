namespace py today
namespace php today

typedef i32 int
typedef string obj_id

struct User {
    1: int id
    2: string username
}

struct Comment {
    1: int id
    2: User user
    3: string text
}

struct Post {
    1: int id
    2: string text
    3: User user
}

exception NotFoundError {
  1: string why
}

exception AlreadyExistsError {
  1: string why
}

exception InputValidationError {
  1: string why
}

exception InvalidRequest {
  1: string why
}

service TodayInternalApiService
{
    // post
    int post_create(1: int user_id, 2: string text),

    Post post_get(1: int user_id, 2: int post_id),

    list <Post> post_list(1: int user_id),

    bool post_delete(1: int user_id, 2: int post_id)
            throws (1: NotFoundError not_found_error),

    // comment
    bool post_comment_create(1: int user_id, 2: int post_id, 3: string text),

    list <Comment> post_comment_list(1: int user_id, 2: int post_id),

    bool post_comment_delete(1: int user_id, 2: int post_id, 3: int comment_id),

    // friend
    list <int> friend_ids(1: int user_id),

    bool friend_remove(1: int actor_id, 2: int target_id),

    // friendship
    list <int> friendship_incoming(1: int user_id),

    list <int> friendship_outgoing(1: int user_id),

    bool friendship_create(1: int actor_id, 2: int target_id)
            throws (1: InputValidationError validation_err, 2: AlreadyExistsError already_exists_err),

    bool friendship_cancel(1: int actor_id, 2: int target_id)
            throws (1: InvalidRequest invalid_request, 2: NotFoundError not_found_error),

    bool friendship_accept(1: int actor_id, 2: int target_id)
            throws (1: InputValidationError validation_err, 2: NotFoundError not_found_error),

    bool friendship_reject(1: int actor_id, 2: int target_id)
            throws (1: InputValidationError validation_err, 2: NotFoundError not_found_error),

    // user

    User users_get(1: int user_id),
    User users_get_by_username(1: string username),

    // timeline
    list <Post> timeline_home(1: int actor_id),
    list <Post> timeline_user(1: int actor_id),

    // system
    bool system_reset_fixtures()
}
