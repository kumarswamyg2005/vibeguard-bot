export type Database = {
  public: {
    Tables: {
      posts: {
        Row: { id: string }
      }
      profiles: {
        Row: { id: string }
      }
      hidden_table: {
        Row: { id: string }
      }
    }
  }
}
