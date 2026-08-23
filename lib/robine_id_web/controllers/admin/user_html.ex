defmodule RobineIdWeb.Admin.UserHTML do
  use RobineIdWeb, :html
  embed_templates "user_html/*"

  def user_edit_path(id) do
    encoded_id = URI.encode(id, &URI.char_unreserved?/1)
    RobineId.Runtime.path("/admin/users/#{encoded_id}/edit")
  end

  def user_path(id) do
    encoded_id = URI.encode(id, &URI.char_unreserved?/1)
    RobineId.Runtime.path("/admin/users/#{encoded_id}")
  end
end
